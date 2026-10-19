<?php
/**
 * Passkeys ( WebAuthn ) without an external library: minimal CBOR/COSE reader, ES256 and RS256,
 * attestation "none" ( the attestation statement is not evaluated ), user verification is always required.
 *
 * The browser must reach the site on the configured home URL ( https, stable host ); passkeys are bound to that host.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Webauthn {

	const TTL = 300;

	public static function supported() {
		return function_exists( 'openssl_verify' ) && function_exists( 'random_bytes' ) && in_array( 'sha256', openssl_get_md_methods( true ), true );
	}

	/* ---- helpers ---- */

	public static function b64u_encode( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' );
	}

	public static function b64u_decode( $s ) {
		$s = (string) $s;
		if ( '' === $s || ! preg_match( '/^[A-Za-z0-9_-]+$/', $s ) ) {
			return '';
		}
		$d = base64_decode( strtr( $s, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $s ) % 4 ) % 4 ), true );
		return false === $d ? '' : $d;
	}

	public static function rp_id() {
		$host = wp_parse_url( home_url(), PHP_URL_HOST );
		return apply_filters( 'empedia_cloud_webauthn_rp_id', strtolower( (string) $host ) );
	}

	/** @return string[] allowed origins ( scheme://host[:port] ) */
	public static function origins() {
		$list = array();
		foreach ( array( home_url(), site_url() ) as $u ) {
			$p = wp_parse_url( $u );
			if ( empty( $p['scheme'] ) || empty( $p['host'] ) ) {
				continue;
			}
			$o = strtolower( $p['scheme'] . '://' . $p['host'] );
			if ( ! empty( $p['port'] ) && ! ( 'https' === $p['scheme'] && 443 === (int) $p['port'] ) && ! ( 'http' === $p['scheme'] && 80 === (int) $p['port'] ) ) {
				$o .= ':' . (int) $p['port'];
			}
			$list[] = $o;
		}
		return array_values( array_unique( apply_filters( 'empedia_cloud_webauthn_origins', $list ) ) );
	}

	/** Passkeys only work in a secure context ( https or localhost ). */
	public static function usable() {
		if ( ! self::supported() ) {
			return false;
		}
		$h = self::rp_id();
		return 0 === strpos( home_url(), 'https://' ) || 'localhost' === $h || '127.0.0.1' === $h;
	}

	private static function err( $code ) {
		if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
			error_log( 'EMPEDIAcloud passkey: ' . $code ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		}
		return new WP_Error( 'empedia_wa_' . $code, __( 'The passkey could not be verified.', 'empedia-shield' ) );
	}

	/* ---- CBOR ( definite lengths only ) ---- */

	public static function cbor_decode( $data, &$pos = 0, $depth = 0 ) {
		if ( $depth > 8 || $pos >= strlen( $data ) ) {
			throw new Exception( 'cbor' );
		}
		$ib    = ord( $data[ $pos++ ] );
		$major = $ib >> 5;
		$info  = $ib & 0x1F;
		if ( 7 === $major ) {
			if ( 20 === $info ) {
				return false;
			}
			if ( 21 === $info ) {
				return true;
			}
			if ( 22 === $info || 23 === $info ) {
				return null;
			}
			throw new Exception( 'cbor' );
		}
		if ( $info < 24 ) {
			$n = $info;
		} elseif ( $info <= 27 ) {
			$bytes = array( 24 => 1, 25 => 2, 26 => 4, 27 => 8 )[ $info ];
			if ( $pos + $bytes > strlen( $data ) ) {
				throw new Exception( 'cbor' );
			}
			$n = 0;
			for ( $i = 0; $i < $bytes; $i++ ) {
				$n = ( $n << 8 ) | ord( $data[ $pos++ ] );
			}
			if ( $n < 0 ) {
				throw new Exception( 'cbor' );
			}
		} else {
			throw new Exception( 'cbor' );
		}
		switch ( $major ) {
			case 0:
				return $n;
			case 1:
				return -1 - $n;
			case 2:
			case 3:
				if ( $n > 65536 || $pos + $n > strlen( $data ) ) {
					throw new Exception( 'cbor' );
				}
				$s    = substr( $data, $pos, $n );
				$pos += $n;
				return $s;
			case 4:
				if ( $n > 64 ) {
					throw new Exception( 'cbor' );
				}
				$a = array();
				for ( $i = 0; $i < $n; $i++ ) {
					$a[] = self::cbor_decode( $data, $pos, $depth + 1 );
				}
				return $a;
			case 5:
				if ( $n > 64 ) {
					throw new Exception( 'cbor' );
				}
				$m = array();
				for ( $i = 0; $i < $n; $i++ ) {
					$k = self::cbor_decode( $data, $pos, $depth + 1 );
					if ( ! is_int( $k ) && ! is_string( $k ) ) {
						throw new Exception( 'cbor' );
					}
					$m[ $k ] = self::cbor_decode( $data, $pos, $depth + 1 );
				}
				return $m;
			case 6:
				return self::cbor_decode( $data, $pos, $depth + 1 );
		}
		throw new Exception( 'cbor' );
	}

	/* ---- DER / COSE ---- */

	private static function der_len( $n ) {
		if ( $n < 128 ) {
			return chr( $n );
		}
		$b = ltrim( pack( 'N', $n ), "\0" );
		return chr( 0x80 | strlen( $b ) ) . $b;
	}

	private static function der( $tag, $body ) {
		return chr( $tag ) . self::der_len( strlen( $body ) ) . $body;
	}

	private static function der_int( $bin ) {
		$bin = ltrim( $bin, "\0" );
		if ( '' === $bin || ord( $bin[0] ) > 127 ) {
			$bin = "\0" . $bin;
		}
		return self::der( 0x02, $bin );
	}

	private static function pem( $der ) {
		return "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $der ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
	}

	/** COSE key → array( pem, alg ) or null. */
	public static function cose_to_pem( $k ) {
		if ( ! is_array( $k ) || ! isset( $k[1], $k[3] ) ) {
			return null;
		}
		if ( 2 === $k[1] && -7 === $k[3] && isset( $k[-1], $k[-2], $k[-3] ) && 1 === $k[-1] && 32 === strlen( (string) $k[-2] ) && 32 === strlen( (string) $k[-3] ) ) {
			$spki = hex2bin( '3059301306072a8648ce3d020106082a8648ce3d030107034200' ) . "\x04" . $k[-2] . $k[-3];
			return array( self::pem( $spki ), -7 );
		}
		if ( 3 === $k[1] && -257 === $k[3] && isset( $k[-1], $k[-2] ) && strlen( (string) $k[-1] ) >= 256 && strlen( (string) $k[-1] ) <= 1024 ) {
			$rsa  = self::der( 0x30, self::der_int( $k[-1] ) . self::der_int( $k[-2] ) );
			$spki = self::der( 0x30, hex2bin( '300d06092a864886f70d0101010500' ) . self::der( 0x03, "\0" . $rsa ) );
			return array( self::pem( $spki ), -257 );
		}
		return null;
	}

	/* ---- challenge storage ---- */

	private static function store( $data ) {
		$ticket = self::b64u_encode( random_bytes( 24 ) );
		// Stored as text: the database column cannot hold arbitrary bytes.
		$data['challenge'] = self::b64u_encode( random_bytes( 32 ) );
		set_transient( 'empedia_wa_' . hash( 'sha256', $ticket ), $data, self::TTL );
		return array( $ticket, $data['challenge'] );
	}

	/** One time: the entry is removed whether or not the verification succeeds. */
	private static function take( $ticket, $type ) {
		$h   = hash( 'sha256', (string) $ticket );
		$key = 'empedia_wa_' . $h;
		$d   = get_transient( $key );
		delete_transient( $key );
		// claimed atomically: of several parallel requests with the same ticket only one gets through
		if ( ! is_array( $d ) || ! isset( $d['type'] ) || $d['type'] !== $type || ! Empedia_Cloud_Atomic::claim( 'wa:' . $h, self::TTL + 60 ) ) {
			return null;
		}
		return $d;
	}

	/** Stable random handle of the user ( never the numeric ID ). */
	public static function user_handle( $user_id ) {
		$h = get_user_meta( $user_id, 'empedia_wa_handle', true );
		if ( ! is_string( $h ) || strlen( $h ) < 20 ) {
			$h = self::b64u_encode( random_bytes( 32 ) );
			update_user_meta( $user_id, 'empedia_wa_handle', $h );
		}
		return $h;
	}

	public static function credentials( $user_id ) {
		$c = get_user_meta( $user_id, 'empedia_passkeys', true );
		return is_array( $c ) ? $c : array();
	}

	/* ---- registration ---- */

	public static function registration_options( $user ) {
		list( $ticket, $challenge ) = self::store( array( 'type' => 'create', 'user_id' => (int) $user->ID ) );
		$exclude = array();
		foreach ( self::credentials( $user->ID ) as $c ) {
			$exclude[] = array( 'type' => 'public-key', 'id' => $c['id'] );
		}
		return array(
			'ticket'    => $ticket,
			'publicKey' => array(
				'rp'                     => array( 'name' => wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ), 'id' => self::rp_id() ),
				'user'                   => array( 'id' => self::user_handle( $user->ID ), 'name' => $user->user_login, 'displayName' => $user->display_name ),
				'challenge'              => $challenge,
				'pubKeyCredParams'       => array( array( 'type' => 'public-key', 'alg' => -7 ), array( 'type' => 'public-key', 'alg' => -257 ) ),
				'timeout'                => 120000,
				'attestation'            => 'none',
				'excludeCredentials'     => $exclude,
				'authenticatorSelection' => array( 'residentKey' => 'preferred', 'userVerification' => 'required' ),
			),
		);
	}

	/** @return array|WP_Error the credential record to store */
	public static function registration_finish( $user, $ticket, $resp, $name = '', $attachment = '' ) {
		$st = self::take( $ticket, 'create' );
		if ( ! $st || (int) $st['user_id'] !== (int) $user->ID || ! is_array( $resp ) ) {
			return self::err( 'ticket' );
		}
		$cdj = self::b64u_decode( isset( $resp['clientDataJSON'] ) ? $resp['clientDataJSON'] : '' );
		$att = self::b64u_decode( isset( $resp['attestationObject'] ) ? $resp['attestationObject'] : '' );
		$cd  = json_decode( $cdj, true );
		if ( ! is_array( $cd ) || ( isset( $cd['type'] ) ? $cd['type'] : '' ) !== 'webauthn.create' || ! hash_equals( (string) $st['challenge'], (string) ( isset( $cd['challenge'] ) ? $cd['challenge'] : '' ) ) || ! in_array( isset( $cd['origin'] ) ? $cd['origin'] : '', self::origins(), true ) ) {
			return self::err( 'client' );
		}
		try {
			$pos = 0;
			$obj = self::cbor_decode( $att, $pos );
			if ( ! is_array( $obj ) || empty( $obj['authData'] ) ) {
				return self::err( 'attestation' );
			}
			$ad = $obj['authData'];
			if ( strlen( $ad ) < 55 || ! hash_equals( hash( 'sha256', self::rp_id(), true ), substr( $ad, 0, 32 ) ) ) {
				return self::err( 'rp' );
			}
			$flags = ord( $ad[32] );
			if ( ! ( $flags & 0x01 ) || ! ( $flags & 0x04 ) || ! ( $flags & 0x40 ) ) {
				return self::err( 'flags' );
			}
			$count = unpack( 'N', substr( $ad, 33, 4 ) )[1];
			$len   = unpack( 'n', substr( $ad, 53, 2 ) )[1];
			if ( $len < 16 || $len > 1023 || strlen( $ad ) < 55 + $len ) {
				return self::err( 'cred' );
			}
			$cid = substr( $ad, 55, $len );
			$p   = 55 + $len;
			$key = self::cbor_decode( $ad, $p );
		} catch ( Exception $e ) {
			return self::err( 'cbor' );
		}
		$pk = self::cose_to_pem( $key );
		if ( ! $pk || false === openssl_pkey_get_public( $pk[0] ) ) {
			return self::err( 'alg' );
		}
		$id = self::b64u_encode( $cid );
		if ( isset( $resp['id'] ) && (string) $resp['id'] !== $id ) {
			return self::err( 'id' );
		}
		foreach ( self::credentials( $user->ID ) as $c ) {
			if ( $c['id'] === $id ) {
				return self::err( 'duplicate' );
			}
		}
		$name = trim( wp_strip_all_tags( (string) $name ) );
		if ( '' === $name ) {
			$name = self::default_name( substr( $ad, 37, 16 ), $attachment );
		}
		return array(
			'id'      => $id,
			'key'     => $pk[0],
			'alg'     => $pk[1],
			'count'   => (int) $count,
			'name'    => mb_substr( $name, 0, 60 ),
			'created' => time(),
			'used'    => 0,
		);
	}

	/** Well-known authenticators by AAGUID ( only sent when the device shares it; Apple and others often send zeros ). */
	private static function aaguid_name( $raw ) {
		$hex = bin2hex( $raw );
		$id  = substr( $hex, 0, 8 ) . '-' . substr( $hex, 8, 4 ) . '-' . substr( $hex, 12, 4 ) . '-' . substr( $hex, 16, 4 ) . '-' . substr( $hex, 20 );
		$map = array(
			'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' => 'iCloud Keychain',
			'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4' => 'Google Password Manager',
			'adce0002-35bc-c60a-648b-0b25f1f05503' => 'Chrome',
			'08987058-cadc-4b81-b6e1-30de50dcbe96' => 'Windows Hello',
			'9ddd1817-af5a-4672-a2b9-3e3dd95000a9' => 'Windows Hello',
			'6028b017-b1d4-4c02-b4b3-afcdafc96bb2' => 'Windows Hello',
			'bada5566-a7aa-401f-bd96-45619a55120d' => '1Password',
			'531126d6-e717-415c-9320-3d9aa6981239' => 'Dashlane',
			'd548826e-79b4-db40-a3d8-11116f7e8349' => 'Bitwarden',
			'2fc0579f-8113-47ea-b116-bb5a8db9202a' => 'YubiKey 5 NFC',
			'cb69481e-8ff7-4039-93ec-0a2729a154a8' => 'YubiKey 5',
		);
		return isset( $map[ $id ] ) ? $map[ $id ] : '';
	}

	/** Device and browser from the User-Agent of the registering browser, for example “iPhone · Safari”. */
	private static function device_label() {
		$ua = isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$os = '';
		foreach ( array( 'iPhone' => 'iPhone', 'iPad' => 'iPad', 'Android' => 'Android', 'Windows' => 'Windows', 'Macintosh' => 'Mac', 'CrOS' => 'Chromebook', 'Linux' => 'Linux' ) as $needle => $label ) {
			if ( false !== stripos( $ua, $needle ) ) {
				$os = $label;
				break;
			}
		}
		$br = '';
		foreach ( array( 'Edg/' => 'Edge', 'OPR/' => 'Opera', 'Firefox/' => 'Firefox', 'Chrome/' => 'Chrome', 'CriOS/' => 'Chrome', 'FxiOS/' => 'Firefox', 'Safari/' => 'Safari' ) as $needle => $label ) {
			if ( false !== strpos( $ua, $needle ) ) {
				$br = $label;
				break;
			}
		}
		return trim( $os . ( $os && $br ? ' · ' : '' ) . $br );
	}

	/** Name when the person gave none: provider ( if the device tells ), device and browser, date. */
	private static function default_name( $aaguid_raw, $attachment ) {
		$parts = array();
		$prov  = '16' === (string) strlen( $aaguid_raw ) ? self::aaguid_name( $aaguid_raw ) : '';
		if ( '' !== $prov ) {
			$parts[] = $prov;
		}
		$dev = self::device_label();
		if ( '' !== $dev ) {
			$parts[] = $dev;
		} elseif ( '' === $prov ) {
			$parts[] = 'platform' === $attachment ? __( 'This device', 'empedia-shield' ) : __( 'Passkey', 'empedia-shield' );
		}
		$parts[] = wp_date( 'j M Y' );
		return implode( ' · ', $parts );
	}

	/* ---- assertion ---- */

	/** $user = null for the passkey sign-in without a user name ( the authenticator chooses ). */
	public static function assertion_options( $user = null ) {
		list( $ticket, $challenge ) = self::store( array( 'type' => 'get', 'user_id' => $user ? (int) $user->ID : 0 ) );
		$allow = array();
		if ( $user ) {
			foreach ( self::credentials( $user->ID ) as $c ) {
				$allow[] = array( 'type' => 'public-key', 'id' => $c['id'] );
			}
		}
		return array(
			'ticket'    => $ticket,
			'publicKey' => array(
				'challenge'        => $challenge,
				'rpId'             => self::rp_id(),
				'timeout'          => 120000,
				'userVerification' => 'required',
				'allowCredentials' => $allow,
			),
		);
	}

	/**
	 * @param int $expect_user user the assertion must belong to ( 0 = take it from the user handle )
	 * @return int|WP_Error user ID
	 */
	public static function assertion_finish( $ticket, $resp, $expect_user = 0 ) {
		$st = self::take( $ticket, 'get' );
		if ( ! $st || ! is_array( $resp ) ) {
			return self::err( 'ticket' );
		}
		// A ticket created for the anonymous passkey sign-in must never be used for a specific user ( and the other way round ).
		if ( (int) $st['user_id'] !== (int) $expect_user ) {
			return self::err( 'user' );
		}
		$cid = (string) ( isset( $resp['id'] ) ? $resp['id'] : '' );
		$cdj = self::b64u_decode( isset( $resp['clientDataJSON'] ) ? $resp['clientDataJSON'] : '' );
		$ad  = self::b64u_decode( isset( $resp['authenticatorData'] ) ? $resp['authenticatorData'] : '' );
		$sig = self::b64u_decode( isset( $resp['signature'] ) ? $resp['signature'] : '' );
		$uid = (int) $st['user_id'];
		if ( ! $uid ) {
			$handle = (string) ( isset( $resp['userHandle'] ) ? $resp['userHandle'] : '' );
			if ( strlen( $handle ) < 20 ) {
				return self::err( 'handle' );
			}
			$ids = get_users( array( 'meta_key' => 'empedia_wa_handle', 'meta_value' => $handle, 'number' => 1, 'fields' => 'ID' ) ); // phpcs:ignore WordPress.DB.SlowDBQuery
			$uid = $ids ? (int) $ids[0] : 0;
		}
		if ( ! $uid || '' === $cdj || '' === $ad || '' === $sig ) {
			return self::err( 'input' );
		}
		$creds = self::credentials( $uid );
		$found = null;
		foreach ( $creds as $i => $c ) {
			if ( hash_equals( $c['id'], $cid ) ) {
				$found = $i;
				break;
			}
		}
		if ( null === $found ) {
			return self::err( 'unknown' );
		}
		$cd = json_decode( $cdj, true );
		if ( ! is_array( $cd ) || ( isset( $cd['type'] ) ? $cd['type'] : '' ) !== 'webauthn.get' || ! hash_equals( (string) $st['challenge'], (string) ( isset( $cd['challenge'] ) ? $cd['challenge'] : '' ) ) || ! in_array( isset( $cd['origin'] ) ? $cd['origin'] : '', self::origins(), true ) ) {
			return self::err( 'client' );
		}
		if ( strlen( $ad ) < 37 || ! hash_equals( hash( 'sha256', self::rp_id(), true ), substr( $ad, 0, 32 ) ) ) {
			return self::err( 'rp' );
		}
		$flags = ord( $ad[32] );
		if ( ! ( $flags & 0x01 ) || ! ( $flags & 0x04 ) ) {
			return self::err( 'flags' );
		}
		$ok = openssl_verify( $ad . hash( 'sha256', $cdj, true ), $sig, $creds[ $found ]['key'], OPENSSL_ALGO_SHA256 );
		if ( 1 !== $ok ) {
			return self::err( 'signature' );
		}
		$count = unpack( 'N', substr( $ad, 33, 4 ) )[1];
		$old   = (int) $creds[ $found ]['count'];
		if ( ( $count || $old ) && $count <= $old ) {
			return self::err( 'counter' ); // cloned authenticator or replay
		}
		$creds[ $found ]['count'] = (int) $count;
		$creds[ $found ]['used']  = time();
		update_user_meta( $uid, 'empedia_passkeys', $creds );
		return $uid;
	}

	public static function add_credential( $user_id, $cred ) {
		$c   = self::credentials( $user_id );
		$c[] = $cred;
		update_user_meta( $user_id, 'empedia_passkeys', array_values( $c ) );
	}

	public static function remove_credential( $user_id, $id ) {
		$c = array_values( array_filter( self::credentials( $user_id ), function ( $x ) use ( $id ) {
			return $x['id'] !== $id;
		} ) );
		if ( $c ) {
			update_user_meta( $user_id, 'empedia_passkeys', $c );
		} else {
			delete_user_meta( $user_id, 'empedia_passkeys' );
		}
	}
}
