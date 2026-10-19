<?php
/**
 * Time based one-time passwords (RFC 6238) and recovery codes. No external library.
 *
 * The secret is stored encrypted (AES-256-GCM, key derived from the WordPress salts), so a copy of the
 * database alone does not reveal it.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Totp {

	const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

	public static function supported() {
		return function_exists( 'openssl_encrypt' ) && function_exists( 'hash_hmac' ) && in_array( 'aes-256-gcm', openssl_get_cipher_methods(), true );
	}

	public static function new_secret() {
		return self::b32_encode( random_bytes( 20 ) );
	}

	public static function b32_encode( $bin ) {
		$bits = '';
		$len  = strlen( $bin );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( ord( $bin[ $i ] ) ), 8, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 5 ) as $chunk ) {
			$out .= self::B32[ bindec( str_pad( $chunk, 5, '0', STR_PAD_RIGHT ) ) ];
		}
		return $out;
	}

	public static function b32_decode( $s ) {
		$s    = strtoupper( preg_replace( '/[^A-Za-z2-7]/', '', (string) $s ) );
		$bits = '';
		$len  = strlen( $s );
		for ( $i = 0; $i < $len; $i++ ) {
			$bits .= str_pad( decbin( strpos( self::B32, $s[ $i ] ) ), 5, '0', STR_PAD_LEFT );
		}
		$out = '';
		foreach ( str_split( $bits, 8 ) as $byte ) {
			if ( 8 === strlen( $byte ) ) {
				$out .= chr( bindec( $byte ) );
			}
		}
		return $out;
	}

	/** Code for a counter value ( 6 digits ). */
	public static function code( $secret_b32, $counter ) {
		$key  = self::b32_decode( $secret_b32 );
		$msg  = pack( 'N2', ( $counter >> 32 ) & 0xFFFFFFFF, $counter & 0xFFFFFFFF );
		$hash = hash_hmac( 'sha1', $msg, $key, true );
		$off  = ord( $hash[19] ) & 0x0F;
		$num  = ( ( ord( $hash[ $off ] ) & 0x7F ) << 24 ) | ( ord( $hash[ $off + 1 ] ) << 16 ) | ( ord( $hash[ $off + 2 ] ) << 8 ) | ord( $hash[ $off + 3 ] );
		return str_pad( (string) ( $num % 1000000 ), 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Checks a code in a window of ±1 step. Returns the matching counter or false.
	 * The caller must reject counters that are not greater than the last accepted one ( replay ).
	 */
	public static function verify( $secret_b32, $input, $now = null ) {
		$input = preg_replace( '/\s+/', '', (string) $input );
		if ( ! preg_match( '/^\d{6}$/', $input ) ) {
			return false;
		}
		$step = (int) floor( ( null === $now ? time() : $now ) / 30 );
		for ( $d = -1; $d <= 1; $d++ ) {
			if ( hash_equals( self::code( $secret_b32, $step + $d ), $input ) ) {
				return $step + $d;
			}
		}
		return false;
	}

	public static function uri( $secret_b32, $account, $issuer ) {
		return 'otpauth://totp/' . rawurlencode( $issuer . ':' . $account ) . '?secret=' . $secret_b32 . '&issuer=' . rawurlencode( $issuer ) . '&algorithm=SHA1&digits=6&period=30';
	}

	/* ---- storage ---- */

	private static function key() {
		return hash_hkdf( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), 32, 'empedia-cloud-totp' );
	}

	public static function seal( $plain ) {
		$iv  = random_bytes( 12 );
		$tag = '';
		$ct  = openssl_encrypt( $plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $iv, $tag );
		return false === $ct ? '' : base64_encode( $iv . $tag . $ct );
	}

	public static function unseal( $blob ) {
		$raw = base64_decode( (string) $blob, true );
		if ( false === $raw || strlen( $raw ) < 29 ) {
			return '';
		}
		$pt = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
		return false === $pt ? '' : $pt;
	}

	/* ---- recovery codes ---- */

	/** @return array{0: string[], 1: string[]} plain codes ( shown once ) and their hashes. */
	public static function new_recovery_codes( $n = 8 ) {
		$plain  = array();
		$hashes = array();
		for ( $i = 0; $i < $n; $i++ ) {
			$c        = strtolower( substr( bin2hex( random_bytes( 5 ) ), 0, 10 ) );
			$c        = substr( $c, 0, 5 ) . '-' . substr( $c, 5 );
			$plain[]  = $c;
			$hashes[] = hash_hmac( 'sha256', $c, self::key() );
		}
		return array( $plain, $hashes );
	}

	/** Removes and returns true when the code is one of the unused hashes. */
	public static function use_recovery_code( $user_id, $input ) {
		$input = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $input ) );
		if ( 10 !== strlen( $input ) ) {
			return false;
		}
		$input  = substr( $input, 0, 5 ) . '-' . substr( $input, 5 );
		$hash   = hash_hmac( 'sha256', $input, self::key() );
		$stored = get_user_meta( $user_id, 'empedia_recovery', true );
		if ( ! is_array( $stored ) ) {
			return false;
		}
		foreach ( $stored as $i => $h ) {
			// a code is claimed atomically: two parallel requests cannot both use it
			if ( hash_equals( (string) $h, $hash ) && Empedia_Cloud_Atomic::claim( 'rc:' . $user_id . ':' . $hash, 600 ) ) {
				unset( $stored[ $i ] );
				update_user_meta( $user_id, 'empedia_recovery', array_values( $stored ) );
				return true;
			}
		}
		return false;
	}
}
