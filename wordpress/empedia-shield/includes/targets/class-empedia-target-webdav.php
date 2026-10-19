<?php
/**
 * Storage target: WebDAV ( Nextcloud, ownCloud, HiDrive, Hetzner Storage Box, NAS … ).
 *
 * The address is the base URL ( for Nextcloud https://host/remote.php/dav/files/USER ). Folders are created as needed.
 * Redirects are never followed ( the password would travel with them ); https is required except for loopback addresses.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Target_Webdav extends Empedia_Cloud_Target {

	/** @var array|WP_Error|null */
	private $u = null;
	/** @var array Folders known to exist ( path => true ). */
	private $made = array();

	private function parts() {
		if ( null !== $this->u ) {
			return $this->u;
		}
		$u = wp_parse_url( trim( (string) $this->opt( 'url', '' ) ) );
		if ( empty( $u['host'] ) || empty( $u['scheme'] ) || ! in_array( $u['scheme'], array( 'http', 'https' ), true ) ) {
			return $this->u = new WP_Error( 'dav_url', 'url' );
		}
		$loop = in_array( $u['host'], array( 'localhost', '127.0.0.1', '[::1]', '::1' ), true );
		if ( 'https' !== $u['scheme'] && ! $loop ) {
			return $this->u = new WP_Error( 'dav_https', 'https required' );
		}
		$this->u = array(
			'origin' => $u['scheme'] . '://' . $u['host'] . ( isset( $u['port'] ) ? ':' . $u['port'] : '' ),
			'path'   => isset( $u['path'] ) ? trim( $u['path'], '/' ) : '',
		);
		return $this->u;
	}

	/** Absolute path ( below the base URL ) without a slash at the start, unencoded. */
	private function path( $rel ) {
		$u = $this->parts();
		return ( '' === $u['path'] ? '' : $u['path'] . '/' ) . $this->full( $rel );
	}

	private function url( $path ) {
		$u = $this->parts();
		return $u['origin'] . '/' . implode( '/', array_map( 'rawurlencode', explode( '/', trim( $path, '/' ) ) ) );
	}

	/** @return array|WP_Error [ code, body ] */
	private function request( $method, $path, $body = null, array $headers = array(), $dir = false ) {
		$u = $this->parts();
		if ( is_wp_error( $u ) ) {
			return $u;
		}
		$url = '' === trim( $path, '/' ) ? $u['origin'] . '/' : $this->url( $path );
		if ( $dir && '/' !== substr( $url, -1 ) ) {
			$url .= '/';
		}
		$res = wp_remote_request(
			$url,
			array(
				'method'      => $method,
				'timeout'     => 120,
				'redirection' => 0,
				'headers'     => $headers + array( 'Authorization' => 'Basic ' . base64_encode( $this->opt( 'user' ) . ':' . $this->opt( 'password' ) ) ),
				'body'        => $body,
			)
		);
		if ( is_wp_error( $res ) ) {
			return new WP_Error( 'dav_http', 'connection failed' );
		}
		return array(
			'code' => (int) wp_remote_retrieve_response_code( $res ),
			'body' => (string) wp_remote_retrieve_body( $res ),
		);
	}

	private static function fail( array $r ) {
		if ( 401 === $r['code'] || 403 === $r['code'] ) {
			return new WP_Error( 'dav_auth', 'access denied' );
		}
		if ( 404 === $r['code'] ) {
			return new WP_Error( 'dav_notfound', 'not found' );
		}
		return new WP_Error( 'dav_' . $r['code'], 'http ' . $r['code'] );
	}

	/** Creates $path and its parents ( below the base URL ). @return true|WP_Error */
	private function mkdirs( $path ) {
		$u    = $this->parts();
		$have = '' === $u['path'] ? array() : explode( '/', $u['path'] );
		$want = array_values( array_filter( explode( '/', trim( $path, '/' ) ), 'strlen' ) );
		$cur  = '';
		foreach ( $want as $i => $seg ) {
			$cur .= ( '' === $cur ? '' : '/' ) . $seg;
			if ( $i < count( $have ) || isset( $this->made[ $cur ] ) ) { // the base URL itself must exist
				continue;
			}
			$r = $this->request( 'MKCOL', $cur, null, array(), true );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( ! in_array( $r['code'], array( 201, 405, 301, 302, 307, 308 ), true ) && ! ( $r['code'] >= 200 && $r['code'] < 300 ) ) {
				return self::fail( $r );
			}
			$this->made[ $cur ] = true;
		}
		return true;
	}

	public function put( $rel, $data ) {
		$u = $this->parts();
		if ( is_wp_error( $u ) ) {
			return $u;
		}
		$path = $this->path( $rel );
		$dir  = dirname( $path );
		if ( '.' !== $dir ) {
			$m = $this->mkdirs( $dir );
			if ( is_wp_error( $m ) ) {
				return $m;
			}
		}
		$r = $this->request( 'PUT', $path, (string) $data, array( 'Content-Type' => 'application/octet-stream' ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return ( $r['code'] >= 200 && $r['code'] < 300 ) ? true : self::fail( $r );
	}

	public function get( $rel ) {
		$u = $this->parts();
		if ( is_wp_error( $u ) ) {
			return $u;
		}
		$r = $this->request( 'GET', $this->path( $rel ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return 200 === $r['code'] ? $r['body'] : self::fail( $r );
	}

	public function dirs() {
		$u = $this->parts();
		if ( is_wp_error( $u ) ) {
			return $u;
		}
		$path = $this->path( '' );
		$r    = $this->request(
			'PROPFIND',
			$path,
			'<?xml version="1.0" encoding="utf-8"?><d:propfind xmlns:d="DAV:"><d:prop><d:resourcetype/></d:prop></d:propfind>',
			array( 'Depth' => '1', 'Content-Type' => 'application/xml' ),
			true
		);
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( 404 === $r['code'] ) {
			return array(); // nothing saved yet
		}
		if ( 207 !== $r['code'] ) {
			return self::fail( $r );
		}
		if ( strlen( $r['body'] ) > 2097152 || false !== stripos( $r['body'], '<!DOCTYPE' ) || false !== stripos( $r['body'], '<!ENTITY' ) ) {
			return new WP_Error( 'dav_xml', 'xml' );
		}
		$prev = libxml_use_internal_errors( true );
		$x    = simplexml_load_string( $r['body'], 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOCDATA );
		libxml_use_internal_errors( $prev );
		if ( false === $x ) {
			return new WP_Error( 'dav_xml', 'xml' );
		}
		$x->registerXPathNamespace( 'd', 'DAV:' );
		$self = trim( (string) wp_parse_url( $this->url( $path ), PHP_URL_PATH ), '/' );
		$out  = array();
		foreach ( (array) $x->xpath( '//d:response' ) as $resp ) {
			$resp->registerXPathNamespace( 'd', 'DAV:' );
			$href = (string) $resp->children( 'DAV:' )->href;
			$p    = trim( (string) wp_parse_url( $href, PHP_URL_PATH ), '/' );
			if ( '' === $p || $p === $self ) {
				continue;
			}
			if ( ! $resp->xpath( './/d:resourcetype/d:collection' ) ) {
				continue;
			}
			$out[] = rawurldecode( basename( $p ) );
		}
		return $out;
	}

	public function remove( $name ) {
		$u = $this->parts();
		if ( is_wp_error( $u ) ) {
			return $u;
		}
		$name = trim( (string) $name, '/' );
		if ( '' === $name || false !== strpos( $name, '..' ) ) {
			return new WP_Error( 'dav_name', 'name' );
		}
		$r = $this->request( 'DELETE', $this->path( $name ), null, array(), true );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return ( ( $r['code'] >= 200 && $r['code'] < 300 ) || 404 === $r['code'] ) ? true : self::fail( $r );
	}
}
