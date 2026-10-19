<?php
/**
 * Storage target: S3-compatible object storage ( AWS S3, Backblaze B2, Wasabi, Hetzner, IONOS, R2, MinIO, bunny.net … ).
 *
 * Path-style addresses ( https://endpoint/bucket/key ), AWS signature version 4 written without an SDK.
 * The body hash is signed, so a modified part is rejected by the server.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Target_S3 extends Empedia_Cloud_Target {

	const EMPTY_SHA = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

	/** @var array|WP_Error|null Parsed endpoint. */
	private $ep = null;

	/** Endpoint parts or WP_Error ( https only; http only for loopback addresses ). */
	private function endpoint() {
		if ( null !== $this->ep ) {
			return $this->ep;
		}
		$u = wp_parse_url( trim( (string) $this->opt( 'endpoint', '' ) ) );
		if ( empty( $u['host'] ) || empty( $u['scheme'] ) || ! in_array( $u['scheme'], array( 'http', 'https' ), true ) ) {
			return $this->ep = new WP_Error( 's3_endpoint', 'endpoint' );
		}
		$loop = in_array( $u['host'], array( 'localhost', '127.0.0.1', '[::1]', '::1' ), true );
		if ( 'https' !== $u['scheme'] && ! $loop ) {
			return $this->ep = new WP_Error( 's3_https', 'https required' );
		}
		if ( '' === (string) $this->opt( 'bucket', '' ) || '' === (string) $this->opt( 'key', '' ) || '' === (string) $this->opt( 'secret', '' ) ) {
			return $this->ep = new WP_Error( 's3_config', 'config' );
		}
		$this->ep = array(
			'scheme' => $u['scheme'],
			'host'   => $u['host'],
			'port'   => isset( $u['port'] ) ? (int) $u['port'] : 0,
			'prefix' => isset( $u['path'] ) ? rtrim( $u['path'], '/' ) : '',
		);
		return $this->ep;
	}

	private static function enc_path( $p ) {
		return implode( '/', array_map( 'rawurlencode', explode( '/', $p ) ) );
	}

	/**
	 * Signed request. $key = object key ( '' = the bucket itself ), $query = array.
	 *
	 * @return array|WP_Error [ code, body, headers ]
	 */
	private function request( $method, $key, array $query = array(), $body = '', array $extra = array() ) {
		$e = $this->endpoint();
		if ( is_wp_error( $e ) ) {
			return $e;
		}
		$region  = (string) $this->opt( 'region', 'us-east-1' );
		$host    = $e['host'] . ( $e['port'] ? ':' . $e['port'] : '' );
		$uri     = $e['prefix'] . '/' . rawurlencode( (string) $this->opt( 'bucket' ) ) . ( '' === $key ? '' : '/' . self::enc_path( $key ) );
		ksort( $query );
		$qs = array();
		foreach ( $query as $k => $v ) {
			$qs[] = rawurlencode( (string) $k ) . '=' . rawurlencode( (string) $v );
		}
		$qs      = implode( '&', $qs );
		$amz     = gmdate( 'Ymd\THis\Z' );
		$day     = substr( $amz, 0, 8 );
		$payload = '' === $body ? self::EMPTY_SHA : hash( 'sha256', $body );
		$hdrs    = array(
			'host'                 => $host,
			'x-amz-content-sha256' => $payload,
			'x-amz-date'           => $amz,
		);
		ksort( $hdrs );
		$canon_h = '';
		foreach ( $hdrs as $k => $v ) {
			$canon_h .= $k . ':' . trim( $v ) . "\n";
		}
		$signed = implode( ';', array_keys( $hdrs ) );
		$canon  = $method . "\n" . $uri . "\n" . $qs . "\n" . $canon_h . "\n" . $signed . "\n" . $payload;
		$scope  = $day . '/' . $region . '/s3/aws4_request';
		$sts    = "AWS4-HMAC-SHA256\n" . $amz . "\n" . $scope . "\n" . hash( 'sha256', $canon );
		$k      = hash_hmac( 'sha256', $day, 'AWS4' . $this->opt( 'secret' ), true );
		$k      = hash_hmac( 'sha256', $region, $k, true );
		$k      = hash_hmac( 'sha256', 's3', $k, true );
		$k      = hash_hmac( 'sha256', 'aws4_request', $k, true );
		$sig    = hash_hmac( 'sha256', $sts, $k );
		$send   = array(
			'x-amz-content-sha256' => $payload,
			'x-amz-date'           => $amz,
			'Authorization'        => 'AWS4-HMAC-SHA256 Credential=' . $this->opt( 'key' ) . '/' . $scope . ', SignedHeaders=' . $signed . ', Signature=' . $sig,
		) + $extra;
		$url    = $e['scheme'] . '://' . $host . $uri . ( '' === $qs ? '' : '?' . $qs );
		$res    = wp_remote_request(
			$url,
			array(
				'method'      => $method,
				'timeout'     => 120,
				'redirection' => 0,
				'headers'     => $send,
				'body'        => '' === $body ? null : $body,
			)
		);
		if ( is_wp_error( $res ) ) {
			return new WP_Error( 's3_http', 'connection failed' );
		}
		return array(
			'code' => (int) wp_remote_retrieve_response_code( $res ),
			'body' => (string) wp_remote_retrieve_body( $res ),
		);
	}

	private static function fail( array $r ) {
		$c = $r['code'];
		if ( 403 === $c ) {
			return new WP_Error( 's3_auth', 'access denied' );
		}
		if ( 404 === $c ) {
			return new WP_Error( 's3_notfound', 'not found' );
		}
		return new WP_Error( 's3_' . $c, 'http ' . $c );
	}

	/** @return SimpleXMLElement|WP_Error */
	private static function xml( $body ) {
		if ( strlen( $body ) > 4194304 || false !== stripos( $body, '<!DOCTYPE' ) || false !== stripos( $body, '<!ENTITY' ) ) {
			return new WP_Error( 's3_xml', 'xml' );
		}
		$prev = libxml_use_internal_errors( true );
		$x    = simplexml_load_string( $body, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA );
		libxml_use_internal_errors( $prev );
		return false !== $x ? $x : new WP_Error( 's3_xml', 'xml' );
	}

	public function put( $rel, $data ) {
		$r = $this->request( 'PUT', $this->full( $rel ), array(), (string) $data, array( 'Content-Type' => 'application/octet-stream' ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return ( $r['code'] >= 200 && $r['code'] < 300 ) ? true : self::fail( $r );
	}

	public function get( $rel ) {
		$r = $this->request( 'GET', $this->full( $rel ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return 200 === $r['code'] ? $r['body'] : self::fail( $r );
	}

	/** One page of a listing. @return array|WP_Error [ keys, prefixes, next ] */
	private function list_page( $prefix, $delimiter, $token ) {
		$q = array( 'list-type' => '2', 'prefix' => $prefix );
		if ( $delimiter ) {
			$q['delimiter'] = '/';
		}
		if ( $token ) {
			$q['continuation-token'] = $token;
		}
		$r = $this->request( 'GET', '', $q );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( 200 !== $r['code'] ) {
			return self::fail( $r );
		}
		$x = self::xml( $r['body'] );
		if ( is_wp_error( $x ) ) {
			return $x;
		}
		$out = array( 'keys' => array(), 'prefixes' => array(), 'next' => '' );
		foreach ( $x->Contents as $c ) {
			$out['keys'][] = (string) $c->Key;
		}
		foreach ( $x->CommonPrefixes as $c ) {
			$out['prefixes'][] = (string) $c->Prefix;
		}
		if ( 'true' === strtolower( (string) $x->IsTruncated ) && (string) $x->NextContinuationToken ) {
			$out['next'] = (string) $x->NextContinuationToken;
		}
		return $out;
	}

	public function dirs() {
		$b      = $this->base();
		$prefix = '' === $b ? '' : $b . '/';
		$out    = array();
		$token  = '';
		for ( $i = 0; $i < 50; $i++ ) {
			$p = $this->list_page( $prefix, true, $token );
			if ( is_wp_error( $p ) ) {
				return $p;
			}
			foreach ( $p['prefixes'] as $d ) {
				$out[] = trim( substr( $d, strlen( $prefix ) ), '/' );
			}
			if ( '' === $p['next'] ) {
				break;
			}
			$token = $p['next'];
		}
		return $out;
	}

	public function remove( $name ) {
		$name = trim( (string) $name, '/' );
		if ( '' === $name || false !== strpos( $name, '..' ) ) {
			return new WP_Error( 's3_name', 'name' );
		}
		$prefix = $this->full( $name ) . '/';
		for ( $round = 0; $round < 200; $round++ ) { // at most 200 pages ( 200000 objects )
			$p = $this->list_page( $prefix, false, '' ); // always the first page: deleted keys drop out
			if ( is_wp_error( $p ) ) {
				return $p;
			}
			if ( ! $p['keys'] ) {
				return true;
			}
			foreach ( $p['keys'] as $k ) {
				$r = $this->request( 'DELETE', $k );
				if ( is_wp_error( $r ) ) {
					return $r;
				}
				if ( $r['code'] >= 300 && 404 !== $r['code'] ) {
					return self::fail( $r );
				}
			}
		}
		return new WP_Error( 's3_toomany', 'too many objects' );
	}
}
