<?php
/**
 * Sign-in protection: limits for failed attempts, second factor ( authenticator app, recovery codes, passkeys )
 * and passkey sign-in. Works without an EMPEDIAcloud account; nothing here sends data to the cloud
 * except aggregate numbers in the inventory ( blocked attempts, administrators with a second factor ).
 *
 * Emergency switches ( wp-config.php ): EMPEDIA_CLOUD_PROTECT_OFF disables everything in this class,
 * EMPEDIA_CLOUD_2FA_OFF disables only the second factor step.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Protect {

	const OPTION = 'empedia_cloud_protect';
	const STATS  = 'empedia_cloud_protect_stats';

	private static $verified = false;

	public static function defaults() {
		return array(
			'limit_on'       => true,
			'limit_user'     => 5,
			'limit_ip'       => 15,
			'window'         => 15,
			'lock_minutes'   => 10,
			'allowlist'      => '',
			'tfa_totp'       => true,
			'tfa_passkeys'   => true,
			'passkey_login'  => true,
			'enforce_roles'  => array(),
			'ip_source'      => 'remote',
		);
	}

	public static function settings() {
		$o = get_option( self::OPTION, array() );
		$o = is_array( $o ) ? array_merge( self::defaults(), $o ) : self::defaults();
		foreach ( array( 'limit_on', 'tfa_totp', 'tfa_passkeys', 'passkey_login' ) as $k ) {
			$o[ $k ] = (bool) $o[ $k ];
		}
		$o['limit_user']   = max( 3, min( 20, (int) $o['limit_user'] ) );
		$o['limit_ip']     = max( 5, min( 100, (int) $o['limit_ip'] ) );
		$o['window']       = max( 5, min( 120, (int) $o['window'] ) );
		$o['lock_minutes'] = max( 1, min( 240, (int) $o['lock_minutes'] ) );
		$o['ip_source']    = in_array( $o['ip_source'], array( 'remote', 'xff', 'cf', 'real' ), true ) ? $o['ip_source'] : 'remote';
		$o['enforce_roles'] = is_array( $o['enforce_roles'] ) ? array_values( array_map( 'sanitize_key', $o['enforce_roles'] ) ) : array();
		return $o;
	}

	public static function off() {
		return defined( 'EMPEDIA_CLOUD_PROTECT_OFF' ) && EMPEDIA_CLOUD_PROTECT_OFF;
	}

	public static function tfa_off() {
		return self::off() || ( defined( 'EMPEDIA_CLOUD_2FA_OFF' ) && EMPEDIA_CLOUD_2FA_OFF );
	}

	public static function init() {
		if ( self::off() ) {
			return;
		}
		add_filter( 'authenticate', array( __CLASS__, 'guard' ), 99, 3 );
		add_filter( 'authenticate', array( __CLASS__, 'gate' ), 100, 3 );
		add_action( 'application_password_did_authenticate', array( __CLASS__, 'mark_app_password' ), 10, 1 );
		add_action( 'wp_login_failed', array( __CLASS__, 'on_failed' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_success' ), 5, 2 );
		add_action( 'after_password_reset', array( __CLASS__, 'unlock_user' ), 10, 1 );
		add_action( 'wp_login', array( __CLASS__, 'second_factor' ), 99, 2 );
		add_action( 'delete_user', array( __CLASS__, 'forget_user' ) );
		add_action( 'login_form_empedia_2fa', array( __CLASS__, 'page_2fa' ) );
		add_action( 'login_form_empedia_pklogin', array( __CLASS__, 'page_pklogin' ) );
		add_action( 'login_form', array( __CLASS__, 'login_form_button' ) );
		add_action( 'login_enqueue_scripts', array( __CLASS__, 'login_assets' ) );
		add_filter( 'wp_login_errors', array( __CLASS__, 'login_errors' ) );
		add_action( 'admin_init', array( __CLASS__, 'enforce_setup' ) );
		add_action( 'wp_ajax_nopriv_empedia_cloud_pk_options', array( __CLASS__, 'ajax_options' ) );
		add_action( 'wp_ajax_empedia_cloud_pk_options', array( __CLASS__, 'ajax_options' ) );
	}

	/* ------------------------------------------------------------------ client address / limits */

	/** The visitor address as set up in the settings ( default: the connection address ). */
	public static function ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$ip     = $remote;
		$hdr    = array( 'xff' => 'HTTP_X_FORWARDED_FOR', 'cf' => 'HTTP_CF_CONNECTING_IP', 'real' => 'HTTP_X_REAL_IP' );
		$src    = self::settings()['ip_source'];
		if ( isset( $hdr[ $src ] ) && ! empty( $_SERVER[ $hdr[ $src ] ] ) ) {
			$v = (string) $_SERVER[ $hdr[ $src ] ]; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( 'xff' === $src ) {
				$parts = array_map( 'trim', explode( ',', $v ) );
				$v     = end( $parts ); // the address added by our own proxy is the last one
			}
			if ( filter_var( trim( $v ), FILTER_VALIDATE_IP ) ) {
				$ip = trim( $v );
			}
		}
		$ip = apply_filters( 'empedia_cloud_client_ip', $ip );
		if ( preg_match( '/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', (string) $ip, $m ) ) {
			$ip = $m[1];
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	/** Address used for the counters: IPv6 is counted per /64 ( one subscriber gets a whole /64 ). */
	public static function ip_key() {
		$ip = self::ip();
		if ( false !== strpos( $ip, ':' ) ) {
			$bin = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( false !== $bin && 16 === strlen( $bin ) ) {
				if ( "\0\0\0\0\0\0\0\0\0\0\xff\xff" === substr( $bin, 0, 12 ) ) {
					return inet_ntop( substr( $bin, 12 ) ); // IPv4-mapped IPv6 address: count it as the IPv4 address
				}
				return bin2hex( substr( $bin, 0, 8 ) ) . '/64';
			}
		}
		return $ip;
	}

	/** Visitors seem to come from a proxy that the settings do not know about ( every visitor would look the same ). */
	public static function proxy_suspected() {
		if ( 'remote' !== self::settings()['ip_source'] || has_filter( 'empedia_cloud_client_ip' ) ) {
			return false;
		}
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$seen   = ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) || ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) || ! empty( $_SERVER['HTTP_X_REAL_IP'] );
		$public = filter_var( $remote, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
		return $seen && ! $public;
	}

	private static function h( $s ) {
		return substr( hash_hmac( 'sha256', $s, wp_salt( 'auth' ) ), 0, 32 );
	}

	private static function allowlisted( $ip ) {
		$list = preg_split( '/[\s,;]+/', (string) self::settings()['allowlist'], -1, PREG_SPLIT_NO_EMPTY );
		return in_array( $ip, $list, true );
	}

	/** Seconds this address ( alone or with the user ) and the user overall are still locked: array( 'addr' => n, 'user' => n ). */
	public static function locked_detail( $username = '' ) {
		$out = array( 'addr' => 0, 'user' => 0 );
		if ( self::allowlisted( self::ip() ) ) {
			return $out;
		}
		$ip  = self::ip_key();
		$u   = strtolower( (string) $username );
		$now = time();
		$keys = array( 'addr' => array( 'ip:' . $ip, 'u:' . $ip . '|' . $u ), 'user' => '' !== $u ? array( 'uw:' . $u ) : array() );
		foreach ( $keys as $scope => $list ) {
			foreach ( $list as $k ) {
				$until = (int) get_transient( 'empedia_lock_' . self::h( $k ) );
				if ( $until > $now ) {
					$out[ $scope ] = max( $out[ $scope ], $until - $now );
				}
			}
		}
		return $out;
	}

	/** Seconds the pair ( this address, user ) is still locked, 0 = not locked ( either kind of lock ). */
	public static function locked_for( $username = '' ) {
		$d = self::locked_detail( $username );
		return max( $d['addr'], $d['user'] );
	}

	/** Addresses a user signed in from successfully ( hashed, 60 days ): the lock “many addresses guess this account” does not stop them. */
	private static function known_ip( $user_id ) {
		if ( self::proxy_suspected() || '0.0.0.0' === self::ip() ) {
			return false;
		}
		$m = get_user_meta( $user_id, 'empedia_known_ips', true );
		$h = self::h( 'kip:' . self::ip_key() );
		return is_array( $m ) && isset( $m[ $h ] ) && (int) $m[ $h ] > time() - 60 * DAY_IN_SECONDS;
	}

	private static function remember_ip( $user_id ) {
		if ( self::proxy_suspected() || '0.0.0.0' === self::ip() ) {
			return;
		}
		$m = get_user_meta( $user_id, 'empedia_known_ips', true );
		$m = is_array( $m ) ? $m : array();
		$m[ self::h( 'kip:' . self::ip_key() ) ] = time();
		arsort( $m );
		update_user_meta( $user_id, 'empedia_known_ips', array_slice( $m, 0, 20, true ) );
	}

	private static function lock_message( $secs ) {
		/* translators: %d: minutes */
		return sprintf( __( '<strong>Error:</strong> Too many failed attempts. Please try again in %d minutes.', 'empedia-shield' ), max( 1, (int) ceil( $secs / 60 ) ) );
	}

	/** Runs after the other authentication filters: a locked address is refused even with a correct password. */
	public static function guard( $user, $username, $password ) {
		$s = self::settings();
		if ( ! $s['limit_on'] || '' === (string) $username ) {
			return $user;
		}
		$d = self::locked_detail( $username );
		if ( $d['addr'] > 0 ) {
			return new WP_Error( 'empedia_locked', self::lock_message( $d['addr'] ) );
		}
		// Many addresses guessed this account: a correct password from an address that signed in successfully before still gets in
		// ( otherwise bots hammering the user name “admin” would lock the owner out of the site ).
		if ( $d['user'] > 0 && ! ( $user instanceof WP_User && self::known_ip( $user->ID ) ) ) {
			return new WP_Error( 'empedia_locked', self::lock_message( $d['user'] ) );
		}
		return $user;
	}

	public static function on_failed( $username, $error = null ) {
		$s = self::settings();
		if ( ! $s['limit_on'] ) {
			return;
		}
		if ( $error instanceof WP_Error && array_intersect( $error->get_error_codes(), array( 'empedia_locked', 'empty_username', 'empty_password' ) ) ) {
			return;
		}
		// A refused security check ( captcha ) says nothing about guessing the password: it counts for the address, not against the account.
		$kind = $error instanceof WP_Error && in_array( 'empedia_captcha', $error->get_error_codes(), true ) ? 'check' : 'password';
		self::record_failure( (string) $username, $kind );
	}

	/** Counts a failed attempt for the address, the ( address, user ) pair and the user overall; locks when a limit is reached. */
	public static function record_failure( $username, $kind = 'password' ) {
		$s  = self::settings();
		$ip = self::ip_key();
		$u  = strtolower( (string) $username );
		self::stat( 'fail' );
		// Behind a proxy the settings do not know every visitor looks the same: locking by address would lock everybody out, so only count.
		if ( self::allowlisted( self::ip() ) || self::proxy_suspected() ) {
			return;
		}
		$win   = $s['window'] * MINUTE_IN_SECONDS;
		$pairs = array( array( 'u:' . $ip . '|' . $u, $s['limit_user'] ) );
		if ( '0.0.0.0' !== self::ip() ) {
			$pairs[] = array( 'ip:' . $ip, $s['limit_ip'] );
		}
		if ( '' !== $u && 'password' === $kind ) {
			$pairs[] = array( 'uw:' . $u, $s['limit_user'] * 5 ); // many addresses guessing one account
		}
		foreach ( $pairs as $pair ) {
			list( $key, $max ) = $pair;
			if ( Empedia_Cloud_Atomic::hit( 'fail:' . $key, $win ) >= $max ) {
				$lvl  = Empedia_Cloud_Atomic::hit( 'lvl:' . $key, DAY_IN_SECONDS ) - 1;
				$mins = min( 24 * 60, $s['lock_minutes'] * ( 2 ** min( $lvl, 8 ) ) );
				set_transient( 'empedia_lock_' . self::h( $key ), time() + $mins * MINUTE_IN_SECONDS, $mins * MINUTE_IN_SECONDS );
				Empedia_Cloud_Atomic::reset( 'fail:' . $key );
				self::stat( 'lock' );
			}
		}
	}

	public static function on_success( $login, $user ) {
		Empedia_Cloud_Atomic::reset( 'fail:u:' . self::ip_key() . '|' . strtolower( (string) $login ) );
		if ( $user instanceof WP_User ) {
			self::remember_ip( $user->ID );
		}
	}

	/** A completed password reset proves the owner: the account is unlocked ( the address locks stay ). */
	public static function unlock_user( $user ) {
		if ( $user instanceof WP_User ) {
			$k = 'uw:' . strtolower( $user->user_login );
			delete_transient( 'empedia_lock_' . self::h( $k ) );
			Empedia_Cloud_Atomic::reset( 'fail:' . $k );
		}
	}

	private static function stat( $kind ) {
		$st = get_option( self::STATS, array() );
		$st = is_array( $st ) ? $st : array();
		$d  = gmdate( 'Y-m-d' );
		$st[ $d ][ $kind ] = ( isset( $st[ $d ][ $kind ] ) ? (int) $st[ $d ][ $kind ] : 0 ) + 1;
		krsort( $st );
		update_option( self::STATS, array_slice( $st, 0, 14, true ), false );
	}

	/** Numbers of the last 24 h ( today + yesterday is the closest day based figure ). */
	public static function stats() {
		$st = get_option( self::STATS, array() );
		$st = is_array( $st ) ? $st : array();
		$out = array( 'fail' => 0, 'lock' => 0 );
		foreach ( array( gmdate( 'Y-m-d' ), gmdate( 'Y-m-d', time() - DAY_IN_SECONDS ) ) as $d ) {
			foreach ( $out as $k => $v ) {
				$out[ $k ] += isset( $st[ $d ][ $k ] ) ? (int) $st[ $d ][ $k ] : 0;
			}
		}
		return $out;
	}

	/* ------------------------------------------------------------------ second factor: state */

	/** The authenticator secret exists and can be read ( not after the site keys were changed ). */
	public static function has_totp( $user_id ) {
		$m = (string) get_user_meta( $user_id, 'empedia_totp', true );
		return '' !== $m && '' !== Empedia_Cloud_Totp::unseal( $m );
	}

	/** An authenticator secret is stored but unreadable ( WordPress salts changed ): it must be set up again. */
	public static function totp_broken( $user_id ) {
		$m = (string) get_user_meta( $user_id, 'empedia_totp', true );
		return '' !== $m && '' === Empedia_Cloud_Totp::unseal( $m );
	}

	public static function recovery_left( $user_id ) {
		$r = get_user_meta( $user_id, 'empedia_recovery', true );
		return is_array( $r ) ? count( $r ) : 0;
	}

	public static function has_passkeys( $user_id ) {
		return (bool) Empedia_Cloud_Webauthn::credentials( $user_id );
	}

	/** Is a second factor available for the user ( and allowed by the settings )? */
	public static function factors( $user_id ) {
		$s = self::settings();
		return array(
			'totp'    => $s['tfa_totp'] && Empedia_Cloud_Totp::supported() && self::has_totp( $user_id ),
			'passkey' => $s['tfa_passkeys'] && Empedia_Cloud_Webauthn::usable() && self::has_passkeys( $user_id ),
		);
	}

	public static function requires_second_factor( $user_id ) {
		if ( self::tfa_off() ) {
			return false;
		}
		$f = self::factors( $user_id );
		return $f['totp'] || $f['passkey'];
	}

	/** The role setting demands a second factor but none is set up yet. */
	public static function must_set_up( $user ) {
		if ( self::tfa_off() || ! $user instanceof WP_User ) {
			return false;
		}
		$s = self::settings();
		if ( ! $s['enforce_roles'] || ! array_intersect( (array) $user->roles, $s['enforce_roles'] ) ) {
			return false;
		}
		$can = ( $s['tfa_totp'] && Empedia_Cloud_Totp::supported() ) || ( $s['tfa_passkeys'] && Empedia_Cloud_Webauthn::usable() );
		return $can && ! self::requires_second_factor( $user->ID );
	}

	public static function enforce_setup() {
		global $pagenow;
		if ( wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ! is_user_logged_in() ) {
			return;
		}
		if ( in_array( $pagenow, array( 'profile.php', 'admin-post.php', 'admin-ajax.php' ), true ) ) {
			return;
		}
		if ( self::must_set_up( wp_get_current_user() ) ) {
			wp_safe_redirect( admin_url( 'profile.php?empedia_2fa=required#empedia-2fa' ) );
			exit;
		}
	}

	public static function forget_user( $user_id ) {
		foreach ( array( 'empedia_totp', 'empedia_totp_pending', 'empedia_totp_last', 'empedia_recovery', 'empedia_passkeys', 'empedia_wa_handle' ) as $m ) {
			delete_user_meta( $user_id, $m );
		}
	}

	/** Number of administrators with a second factor ( for the inventory ). */
	public static function admins_with_factor() {
		$n = 0;
		foreach ( get_users( array( 'role' => 'administrator', 'fields' => 'ID', 'number' => 500 ) ) as $id ) {
			if ( self::has_totp( $id ) || self::has_passkeys( $id ) ) {
				$n++;
			}
		}
		return $n;
	}

	/* ------------------------------------------------------------------ second factor: sign-in step */

	/** @var array<int,bool> users that signed in with an application password in this request ( a multicall can mix users ) */
	private static $app_users = array();
	const COOKIE = 'empedia_2fa';

	public static function mark_app_password( $user = null ) {
		if ( $user instanceof WP_User ) {
			self::$app_users[ $user->ID ] = true;
		}
	}

	/**
	 * Runs after all other authentication filters. When the password was accepted for a user with a second factor:
	 *  - XML-RPC ( cannot ask for a second code ) is refused unless an application password was used;
	 *  - no login cookie is sent in this request ( wp_signon sets it before "wp_login" fires ), the second step follows.
	 */
	public static function gate( $user, $username, $password ) {
		if ( ! $user instanceof WP_User || self::tfa_off() || ! self::requires_second_factor( $user->ID ) ) {
			return $user;
		}
		if ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST && empty( self::$app_users[ $user->ID ] ) ) {
			return new WP_Error( 'empedia_2fa_xmlrpc', __( '<strong>Error:</strong> This account uses two-factor authentication. Use an application password for XML-RPC.', 'empedia-shield' ) );
		}
		if ( ! self::$verified ) {
			add_filter( 'send_auth_cookies', '__return_false' );
		}
		return $user;
	}

	private static function ticket_key( $ticket ) {
		return 'empedia_2fa_' . hash( 'sha256', (string) $ticket );
	}

	/** After the password was accepted ( no cookie was sent, see gate() ): continue on the second-factor page. */
	public static function second_factor( $user_login, $user ) {
		if ( self::$verified || ! $user instanceof WP_User || ! self::requires_second_factor( $user->ID ) ) {
			return;
		}
		wp_clear_auth_cookie();
		$ticket = Empedia_Cloud_Webauthn::b64u_encode( random_bytes( 24 ) );
		$redir  = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), admin_url() ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the sign-in form carries no nonce; wp_validate_redirect() sanitizes and restricts the address (sanitize_text_field would strip %XX octets).
		set_transient(
			self::ticket_key( $ticket ),
			array(
				'uid'      => (int) $user->ID,
				'login'    => $user->user_login,
				'remember' => ! empty( $_POST['rememberme'] ), // phpcs:ignore WordPress.Security.NonceVerification
				'redirect' => $redir,
			),
			10 * MINUTE_IN_SECONDS
		);
		// The ticket travels in a cookie, not in the address ( logs, Referer ).
		setcookie( self::COOKIE, $ticket, time() + 10 * MINUTE_IN_SECONDS, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		wp_safe_redirect( add_query_arg( 'action', 'empedia_2fa', wp_login_url() ) );
		exit;
	}

	/** Completes a sign-in that was proven elsewhere ( EMPEDIAcloud sign-in ): the cloud account has its own second factor. */
	public static function login_external( $user_id, $remember, $redirect ) {
		self::finish_login( $user_id, $remember, $redirect );
	}

	private static function finish_login( $user_id, $remember, $redirect ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}
		self::$verified = true;
		remove_filter( 'send_auth_cookies', '__return_false' );
		wp_set_current_user( $user_id );
		wp_set_auth_cookie( $user_id, $remember );
		setcookie( self::COOKIE, '', time() - YEAR_IN_SECONDS, COOKIEPATH ? COOKIEPATH : '/', COOKIE_DOMAIN, is_ssl(), true );
		do_action( 'wp_login', $user->user_login, $user ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core hook: the sign-in completes here, after the second factor.
		wp_safe_redirect( $redirect );
		exit;
	}

	private static function ticket_from_request() {
		// phpcs:disable WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		if ( isset( $_COOKIE[ self::COOKIE ] ) ) {
			return sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) );
		}
		return '';
		// phpcs:enable
	}

	public static function page_2fa() {
		$ticket = self::ticket_from_request();
		$key    = self::ticket_key( $ticket );
		$st     = '' === $ticket ? false : get_transient( $key );
		$err    = null;
		if ( ! is_array( $st ) ) {
			wp_safe_redirect( add_query_arg( 'empedia_2fa', 'expired', wp_login_url() ) );
			exit;
		}
		$uid = (int) $st['uid'];
		$f   = self::factors( $uid );
		if ( 'POST' === $_SERVER['REQUEST_METHOD'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$left = self::locked_for( $st['login'] );
			if ( $left > 0 ) {
				$err = new WP_Error( 'locked', self::lock_message( $left ) );
			} elseif ( Empedia_Cloud_Atomic::hit( 'tries:' . $ticket, 10 * MINUTE_IN_SECONDS ) > 5 ) {
				delete_transient( $key );
				wp_safe_redirect( add_query_arg( 'empedia_2fa', 'expired', wp_login_url() ) );
				exit;
			} else {
				if ( self::check_second_factor( $uid, $f ) ) {
					delete_transient( $key );
					self::finish_login( $uid, $st['remember'], $st['redirect'] );
				}
				self::record_failure( $st['login'] );
				$err = new WP_Error( 'bad', __( '<strong>Error:</strong> The code is not valid. Please try again.', 'empedia-shield' ) );
			}
		}
		self::render_2fa( $ticket, $f, $uid, $err );
		exit;
	}

	private static function check_second_factor( $uid, $f ) {
		// phpcs:disable WordPress.Security.NonceVerification -- the one time ticket is the proof of the first step
		if ( ! empty( $_POST['empedia_pk'] ) && $f['passkey'] ) {
			$resp = json_decode( wp_unslash( $_POST['empedia_pk'] ), true ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON of the WebAuthn assertion, verified cryptographically in assertion_finish().
			$tk   = isset( $_POST['pk_ticket'] ) ? sanitize_text_field( wp_unslash( $_POST['pk_ticket'] ) ) : '';
			$res  = Empedia_Cloud_Webauthn::assertion_finish( $tk, $resp, $uid );
			return ! is_wp_error( $res ) && (int) $res === (int) $uid;
		}
		$code = isset( $_POST['empedia_code'] ) ? sanitize_text_field( wp_unslash( $_POST['empedia_code'] ) ) : '';
		// phpcs:enable
		if ( '' === $code ) {
			return false;
		}
		if ( $f['totp'] ) {
			$secret = Empedia_Cloud_Totp::unseal( get_user_meta( $uid, 'empedia_totp', true ) );
			$ctr    = '' === $secret ? false : Empedia_Cloud_Totp::verify( $secret, $code );
			// a code works once: the counter is claimed atomically
			if ( false !== $ctr && $ctr > (int) get_user_meta( $uid, 'empedia_totp_last', true ) && Empedia_Cloud_Atomic::claim( 'totp:' . $uid . ':' . $ctr, 300 ) ) {
				update_user_meta( $uid, 'empedia_totp_last', $ctr );
				return true;
			}
		}
		return Empedia_Cloud_Totp::use_recovery_code( $uid, $code );
	}

	private static function render_2fa( $ticket, $f, $uid, $err ) {
		login_header( __( 'Two-factor authentication', 'empedia-shield' ), '', $err );
		echo '<form name="empedia2fa" id="empedia2fa" action="' . esc_url( add_query_arg( 'action', 'empedia_2fa', wp_login_url() ) ) . '" method="post">';
		echo '<input type="hidden" name="empedia_pk" id="empedia_pk" value=""><input type="hidden" name="pk_ticket" id="empedia_pk_ticket" value="">';
		if ( $f['totp'] || self::recovery_left( $uid ) ) {
			$label = $f['totp'] ? __( 'Authentication code or recovery code', 'empedia-shield' ) : __( 'Recovery code', 'empedia-shield' );
			echo '<p><label for="empedia_code">' . esc_html( $label ) . '</label>';
			echo '<input type="text" name="empedia_code" id="empedia_code" class="input" value="" size="20" autocomplete="one-time-code" inputmode="text"' . ( $f['totp'] ? ' autofocus' : '' ) . '></p>';
			echo '<p class="submit"><input type="submit" class="button button-primary button-large" value="' . esc_attr__( 'Verify', 'empedia-shield' ) . '"></p>';
		} else {
			echo '<p>' . esc_html__( 'Confirm your sign-in with your passkey.', 'empedia-shield' ) . '</p>';
		}
		if ( $f['passkey'] ) {
			echo '<p><button type="button" class="button button-large" id="empedia-pk-2fa" data-ticket="' . esc_attr( $ticket ) . '">' . esc_html__( 'Use a passkey', 'empedia-shield' ) . '</button></p>';
		}
		echo '</form>';
		echo '<p id="backtoblog"><a href="' . esc_url( wp_login_url() ) . '">' . esc_html__( 'Back to sign-in', 'empedia-shield' ) . '</a></p>';
		login_footer();
	}

	/* ------------------------------------------------------------------ passkey sign-in ( first factor ) */

	public static function login_assets() {
		$s = self::settings();
		$f = ( $s['tfa_passkeys'] || $s['passkey_login'] ) && Empedia_Cloud_Webauthn::usable();
		if ( ! $f ) {
			return;
		}
		wp_enqueue_script( 'empedia-cloud-passkey', EMPEDIA_CLOUD_URL_BASE . 'assets/passkey.js', array(), EMPEDIA_CLOUD_VERSION, true );
		wp_localize_script(
			'empedia-cloud-passkey',
			'EmpediaPasskey',
			array(
				'ajax'     => admin_url( 'admin-ajax.php' ),
				'loginUrl' => add_query_arg( 'action', 'empedia_pklogin', wp_login_url() ),
				'i18n'     => array(
					'failed'      => __( 'The passkey could not be used. Please try again or use another method.', 'empedia-shield' ),
					'unsupported' => __( 'This browser does not support passkeys.', 'empedia-shield' ),
				),
			)
		);
	}

	public static function login_form_button() {
		$s = self::settings();
		if ( ! $s['passkey_login'] || ! $s['tfa_passkeys'] || self::tfa_off() || ! Empedia_Cloud_Webauthn::usable() ) {
			return;
		}
		echo '<p class="empedia-pk-login" style="margin-top:12px"><button type="button" class="button button-large" id="empedia-pk-login" style="width:100%">' . esc_html__( 'Sign in with a passkey', 'empedia-shield' ) . '</button></p>';
	}

	/** Simple counter per address for the anonymous endpoints ( each call stores a short-lived entry ). */
	private static function throttled( $bucket, $max, $secs ) {
		return Empedia_Cloud_Atomic::hit( 'thr:' . $bucket . ':' . self::ip_key(), $secs ) > $max;
	}

	/** Options for the browser: purpose=login ( no user ), purpose=2fa ( with the ticket of the first step ). */
	public static function ajax_options() {
		$ip_left = self::locked_for( '' );
		if ( $ip_left > 0 ) {
			wp_send_json_error( array( 'message' => wp_strip_all_tags( self::lock_message( $ip_left ) ) ), 429 );
		}
		if ( self::throttled( 'opt', 40, 10 * MINUTE_IN_SECONDS ) ) {
			wp_send_json_error( array( 'message' => __( 'Too many requests. Please try again later.', 'empedia-shield' ) ), 429 );
		}
		// phpcs:disable WordPress.Security.NonceVerification -- anonymous by design; limited by the failure counter and one time tickets
		$purpose = isset( $_POST['purpose'] ) ? sanitize_key( wp_unslash( $_POST['purpose'] ) ) : '';
		if ( 'register' === $purpose ) {
			self::ajax_register_options();
		}
		if ( 'login' === $purpose ) {
			$s = self::settings();
			if ( ! $s['passkey_login'] || ! $s['tfa_passkeys'] || self::tfa_off() || ! Empedia_Cloud_Webauthn::usable() ) {
				wp_send_json_error( array(), 400 );
			}
			$o = Empedia_Cloud_Webauthn::assertion_options( null );
			// each request is a possible guess: count it lightly against the address
			wp_send_json_success( $o );
		}
		if ( '2fa' === $purpose ) {
			$ticket = self::ticket_from_request();
			$st     = '' === $ticket ? false : get_transient( self::ticket_key( $ticket ) );
			if ( ! is_array( $st ) ) {
				wp_send_json_error( array(), 400 );
			}
			$user = get_userdata( (int) $st['uid'] );
			if ( ! $user || ! self::factors( $user->ID )['passkey'] ) {
				wp_send_json_error( array(), 400 );
			}
			wp_send_json_success( Empedia_Cloud_Webauthn::assertion_options( $user ) );
		}
		// phpcs:enable
		wp_send_json_error( array(), 400 );
	}

	/** Registration of a passkey for the current user ( profile page ). */
	private static function ajax_register_options() {
		if ( ! is_user_logged_in() || ! check_ajax_referer( 'empedia_cloud_passkey', 'nonce', false ) || ! Empedia_Cloud_Webauthn::usable() ) {
			wp_send_json_error( array(), 403 );
		}
		// No password prompt: creating a passkey already needs the device unlock ( fingerprint, face or PIN ); the owner gets an e-mail about every new passkey.
		$u = wp_get_current_user();
		if ( Empedia_Cloud_Atomic::hit( 'pkreg:' . $u->ID, 10 * MINUTE_IN_SECONDS ) > 20 ) {
			wp_send_json_error( array( 'message' => __( 'Too many attempts. Please try again later.', 'empedia-shield' ) ), 429 );
		}
		wp_send_json_success( Empedia_Cloud_Webauthn::registration_options( $u ) );
	}

	public static function page_pklogin() {
		$s = self::settings();
		if ( 'POST' !== $_SERVER['REQUEST_METHOD'] || ! $s['passkey_login'] || ! $s['tfa_passkeys'] || self::tfa_off() ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		$fail = static function () {
			self::record_failure( '' );
			wp_safe_redirect( add_query_arg( 'empedia_pk', 'failed', wp_login_url() ) );
			exit;
		};
		if ( self::locked_for( '' ) > 0 ) {
			wp_safe_redirect( add_query_arg( 'empedia_pk', 'locked', wp_login_url() ) );
			exit;
		}
		// phpcs:disable WordPress.Security.NonceVerification -- the signed challenge is the proof
		$resp = json_decode( isset( $_POST['empedia_pk'] ) ? wp_unslash( $_POST['empedia_pk'] ) : '', true ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON of the WebAuthn assertion, verified cryptographically in assertion_finish().
		$tk   = isset( $_POST['pk_ticket'] ) ? sanitize_text_field( wp_unslash( $_POST['pk_ticket'] ) ) : '';
		$res  = Empedia_Cloud_Webauthn::assertion_finish( $tk, $resp, 0 );
		if ( is_wp_error( $res ) ) {
			$fail();
		}
		$user = get_userdata( $res );
		if ( ! $user || ! self::factors( $res )['passkey'] ) {
			$fail();
		}
		// The same gates as a password sign-in ( disabled or unapproved accounts, spam users on multisite ).
		if ( function_exists( 'wp_authenticate_spam_check' ) && is_wp_error( wp_authenticate_spam_check( $user ) ) ) {
			$fail();
		}
		if ( is_wp_error( apply_filters( 'wp_authenticate_user', $user, '' ) ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter: same gates as a password sign-in.
			$fail();
		}
		$redir = isset( $_POST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_POST['redirect_to'] ), admin_url() ) : admin_url(); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- wp_validate_redirect() sanitizes and restricts the address.
		$rem   = ! empty( $_POST['rememberme'] );
		// phpcs:enable
		self::finish_login( $res, $rem, $redir );
	}

	public static function login_errors( $errors ) {
		// phpcs:disable WordPress.Security.NonceVerification
		if ( isset( $_GET['empedia_pk'] ) ) {
			$errors->add( 'empedia_pk', 'locked' === $_GET['empedia_pk'] ? self::lock_message( max( 60, self::locked_for( '' ) ) ) : __( '<strong>Error:</strong> The passkey could not be used.', 'empedia-shield' ) );
		}
		if ( isset( $_GET['empedia_2fa'] ) && 'expired' === $_GET['empedia_2fa'] ) {
			$errors->add( 'empedia_2fa', __( '<strong>Error:</strong> The second step expired. Please sign in again.', 'empedia-shield' ) );
		}
		// phpcs:enable
		return $errors;
	}
}
