<?php
/**
 * Sign in with the EMPEDIAcloud account: OpenID Connect ( authorization code with PKCE ) against empedia.cloud.
 *
 * The cloud only vouches for the identity ( verified e-mail address, member of the organization this site belongs to ).
 * An account is never created here: the visitor must already have an account on this site with the same address.
 * The password sign-in stays available; EMPEDIA_CLOUD_SSO_OFF in wp-config.php switches this off.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Sso {

	const OPTION  = 'empedia_cloud_sso';
	const COOKIE  = 'empedia_sso_st';
	const META    = 'empedia_sso_sub';
	const TTL     = 600;

	public static function off() {
		return Empedia_Cloud_Protect::off() || ( defined( 'EMPEDIA_CLOUD_SSO_OFF' ) && EMPEDIA_CLOUD_SSO_OFF );
	}

	public static function settings() {
		$o = get_option( self::OPTION, array() );
		$o = is_array( $o ) ? $o : array();
		return array(
			'enabled'   => ! empty( $o['enabled'] ),
			'client_id' => isset( $o['client_id'] ) ? preg_replace( '/[^A-Za-z0-9_]/', '', (string) $o['client_id'] ) : '',
		);
	}

	/** Sign-in is offered: connected, switched on, no emergency constant. */
	public static function active() {
		$s = self::settings();
		return ! self::off() && $s['enabled'] && '' !== $s['client_id'] && Empedia_Cloud_Client::is_connected();
	}

	public static function redirect_uri() {
		return add_query_arg( 'action', 'empedia_sso', wp_login_url() );
	}

	public static function init() {
		add_action( 'login_form_empedia_sso', array( __CLASS__, 'handle' ) );
		add_action( 'login_form', array( __CLASS__, 'login_button' ) );
		add_filter( 'wp_login_errors', array( __CLASS__, 'login_errors' ) );
		add_action( 'delete_user', array( __CLASS__, 'forget_user' ) );
	}

	public static function forget_user( $user_id ) {
		delete_user_meta( $user_id, self::META );
	}

	/* ------------------------------------------------------------------ login page */

	public static function login_button() {
		if ( ! self::active() ) {
			return;
		}
		// phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- the sign-in form carries no nonce; wp_validate_redirect() sanitizes the address.
		$to  = isset( $_REQUEST['redirect_to'] ) ? wp_validate_redirect( wp_unslash( $_REQUEST['redirect_to'] ), '' ) : '';
		$url = add_query_arg( array( 'action' => 'empedia_sso', 'redirect_to' => '' !== $to ? rawurlencode( $to ) : false ), wp_login_url() );
		echo '<p class="empedia-sso-login" style="margin-top:12px"><a class="button button-large" href="' . esc_url( $url ) . '" style="width:100%;text-align:center;box-sizing:border-box">' . esc_html__( 'Sign in with EMPEDIAcloud', 'empedia-shield' ) . '</a></p>';
	}

	public static function login_errors( $errors ) {
		if ( isset( $_GET['empedia_sso'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			$map = array(
				'denied'  => __( '<strong>Error:</strong> Your EMPEDIAcloud account may not sign in to this site.', 'empedia-shield' ),
				'nomatch' => __( '<strong>Error:</strong> No account on this site matches your EMPEDIAcloud account. Ask an administrator to create one with the same e-mail address.', 'empedia-shield' ),
				'expired' => __( '<strong>Error:</strong> The sign-in took too long. Please try again.', 'empedia-shield' ),
				'locked'  => __( '<strong>Error:</strong> Too many failed attempts. Please try again later.', 'empedia-shield' ),
			);
			$k = sanitize_key( wp_unslash( $_GET['empedia_sso'] ) ); // phpcs:ignore WordPress.Security.NonceVerification
			$errors->add( 'empedia_sso', isset( $map[ $k ] ) ? $map[ $k ] : __( '<strong>Error:</strong> The sign-in with EMPEDIAcloud failed. Please try again or use your password.', 'empedia-shield' ) );
		}
		return $errors;
	}

	private static function back( $code ) {
		setcookie( self::COOKIE, '', array( 'expires' => time() - YEAR_IN_SECONDS, 'path' => COOKIEPATH ? COOKIEPATH : '/', 'domain' => COOKIE_DOMAIN, 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax' ) );
		wp_safe_redirect( add_query_arg( 'empedia_sso', $code, wp_login_url() ) );
		exit;
	}

	private static function h( $v ) {
		return substr( hash_hmac( 'sha256', (string) $v, wp_salt( 'auth' ) ), 0, 40 );
	}

	/* ------------------------------------------------------------------ flow */

	/** One entry point: without a state it starts the flow, with a state it is the return from the cloud. */
	public static function handle() {
		if ( ! self::active() ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}
		if ( Empedia_Cloud_Atomic::hit( 'sso:' . Empedia_Cloud_Protect::ip_key(), 10 * MINUTE_IN_SECONDS ) > 40 ) {
			self::back( 'locked' );
		}
		if ( Empedia_Cloud_Protect::locked_for( '' ) > 0 ) {
			self::back( 'locked' );
		}
		// phpcs:disable WordPress.Security.NonceVerification -- the state bound to this browser is the proof
		if ( isset( $_GET['state'] ) ) {
			self::callback();
		}
		self::start();
		// phpcs:enable
	}

	private static function start() {
		$state    = bin2hex( random_bytes( 16 ) );
		$verifier = rtrim( strtr( base64_encode( random_bytes( 48 ) ), '+/', '-_' ), '=' );
		$to       = isset( $_GET['redirect_to'] ) ? wp_validate_redirect( rawurldecode( wp_unslash( $_GET['redirect_to'] ) ), admin_url() ) : admin_url(); // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- start of the sign-in (no nonce); wp_validate_redirect() sanitizes the address.
		set_transient( 'empedia_sso_' . self::h( $state ), array( 'v' => $verifier, 'to' => $to ), self::TTL );
		setcookie( self::COOKIE, $state, array( 'expires' => time() + self::TTL, 'path' => COOKIEPATH ? COOKIEPATH : '/', 'domain' => COOKIE_DOMAIN, 'secure' => is_ssl(), 'httponly' => true, 'samesite' => 'Lax' ) );
		$s   = self::settings();
		$url = Empedia_Cloud_Client::base() . '/oauth/authorize?' . http_build_query(
			array(
				'response_type'         => 'code',
				'client_id'             => $s['client_id'],
				'redirect_uri'          => self::redirect_uri(),
				'scope'                 => 'openid email profile',
				'state'                 => $state,
				'code_challenge'        => rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ),
				'code_challenge_method' => 'S256',
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
		// phpcs:ignore WordPress.Security.SafeRedirect -- the address of the cloud configured for this plugin
		wp_redirect( $url );
		exit;
	}

	private static function fail( $code = 'failed' ) {
		self::back( $code ); // counted by the per-address throttle in handle(), not by the password lockout
	}

	private static function callback() {
		$state  = isset( $_GET['state'] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_GET['state'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- the return from EMPEDIAcloud is bound to the browser by the state cookie, no form of ours.
		$cookie = isset( $_COOKIE[ self::COOKIE ] ) ? preg_replace( '/[^a-f0-9]/', '', sanitize_text_field( wp_unslash( $_COOKIE[ self::COOKIE ] ) ) ) : '';
		if ( 32 !== strlen( $state ) || ! hash_equals( $cookie, $state ) ) {
			self::fail( 'expired' ); // not the browser that started it ( or a replay )
		}
		$key = 'empedia_sso_' . self::h( $state );
		$st  = get_transient( $key );
		delete_transient( $key );
		if ( ! is_array( $st ) || ! Empedia_Cloud_Atomic::claim( 'sso:st:' . self::h( $state ), self::TTL ) ) {
			self::back( 'expired' );
		}
		if ( isset( $_GET['error'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			self::back( 'access_denied' === sanitize_key( wp_unslash( $_GET['error'] ) ) ? 'denied' : 'failed' ); // phpcs:ignore WordPress.Security.NonceVerification
		}
		$code = isset( $_GET['code'] ) ? preg_replace( '/[^A-Za-z0-9_\-]/', '', sanitize_text_field( wp_unslash( $_GET['code'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification
		if ( '' === $code ) {
			self::fail();
		}
		$s   = self::settings();
		$tok = wp_remote_post(
			Empedia_Cloud_Client::base() . '/oauth/token',
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => array( 'Accept' => 'application/json' ),
				'body'        => array(
					'grant_type'    => 'authorization_code',
					'code'          => $code,
					'redirect_uri'  => self::redirect_uri(),
					'client_id'     => $s['client_id'],
					'code_verifier' => $st['v'],
				),
			)
		);
		$tj = is_wp_error( $tok ) || 200 !== (int) wp_remote_retrieve_response_code( $tok ) ? null : json_decode( wp_remote_retrieve_body( $tok ), true );
		if ( ! is_array( $tj ) || empty( $tj['access_token'] ) ) {
			self::fail( is_array( $tj ) || is_wp_error( $tok ) ? 'failed' : 'denied' );
		}
		$ui = wp_remote_get(
			Empedia_Cloud_Client::base() . '/oauth/userinfo',
			array(
				'timeout'     => 15,
				'redirection' => 0,
				'headers'     => array( 'Authorization' => 'Bearer ' . $tj['access_token'], 'Accept' => 'application/json' ),
			)
		);
		$uj = is_wp_error( $ui ) || 200 !== (int) wp_remote_retrieve_response_code( $ui ) ? null : json_decode( wp_remote_retrieve_body( $ui ), true );
		// Revoke the short-lived token again: it was only needed for this one call.
		wp_remote_post( Empedia_Cloud_Client::base() . '/oauth/revoke', array( 'timeout' => 5, 'redirection' => 0, 'body' => array( 'token' => $tj['access_token'], 'client_id' => $s['client_id'] ) ) );
		if ( ! is_array( $uj ) || empty( $uj['sub'] ) || empty( $uj['email'] ) || empty( $uj['email_verified'] ) || ! is_email( $uj['email'] ) ) {
			self::fail();
		}
		$sub  = substr( preg_replace( '/[^A-Za-z0-9\-_]/', '', (string) $uj['sub'] ), 0, 64 );
		$user = get_user_by( 'email', sanitize_email( $uj['email'] ) );
		if ( ! $user || ( is_multisite() && ! is_user_member_of_blog( $user->ID ) ) || '' === $sub ) {
			self::fail( 'nomatch' );
		}
		$known = (string) get_user_meta( $user->ID, self::META, true );
		if ( '' !== $known && ! hash_equals( $known, $sub ) ) {
			self::fail( 'nomatch' ); // this account was linked to another EMPEDIAcloud account before
		}
		// The same gates as a password sign-in ( disabled or unapproved accounts, spam users on multisite ).
		if ( function_exists( 'wp_authenticate_spam_check' ) && is_wp_error( wp_authenticate_spam_check( $user ) ) ) {
			self::fail( 'nomatch' );
		}
		if ( is_wp_error( apply_filters( 'wp_authenticate_user', $user, '' ) ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- WordPress core filter: same gates as a password sign-in.
			self::fail( 'nomatch' );
		}
		if ( '' === $known && ! user_can( $user, 'edit_posts' ) ) {
			self::fail( 'nomatch' ); // never bind a first link to a plain subscriber ( open registration does not verify the e-mail address )
		}
		if ( '' === $known ) {
			update_user_meta( $user->ID, self::META, $sub );
		}
		Empedia_Cloud_Protect::login_external( $user->ID, false, $st['to'] );
	}

	/* ------------------------------------------------------------------ settings ( called from the sign-in protection tab ) */

	public static function register_admin() {
		add_action( 'admin_post_empedia_cloud_sso_enable', array( __CLASS__, 'handle_enable' ) );
		add_action( 'admin_post_empedia_cloud_sso_disable', array( __CLASS__, 'handle_disable' ) );
	}

	private static function admin_guard( $action ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( $action );
	}

	public static function handle_enable() {
		self::admin_guard( 'empedia_cloud_sso_enable' );
		$r = Empedia_Cloud_Client::request( 'POST', '/sso', array( 'redirect_uri' => self::redirect_uri() ), true, 15 );
		if ( is_wp_error( $r ) ) {
			Empedia_Cloud_Admin::flash( 'error', 'empedia_pro_required' === $r->get_error_code() ? __( 'Signing in with EMPEDIAcloud is part of the Pro level of this site.', 'empedia-shield' ) : $r->get_error_message() );
		} else {
			update_option( self::OPTION, array( 'enabled' => true, 'client_id' => isset( $r['client_id'] ) ? (string) $r['client_id'] : '' ), false );
			Empedia_Cloud_Admin::flash( 'success', __( 'Signing in with EMPEDIAcloud is on.', 'empedia-shield' ) );
		}
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'login' ) );
		exit;
	}

	public static function handle_disable() {
		self::admin_guard( 'empedia_cloud_sso_disable' );
		self::switch_off();
		Empedia_Cloud_Admin::flash( 'success', __( 'Signing in with EMPEDIAcloud is off.', 'empedia-shield' ) );
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'login' ) );
		exit;
	}

	/** Ends the app in the cloud ( best effort ) and forgets it here. */
	public static function switch_off() {
		if ( Empedia_Cloud_Client::is_connected() ) {
			Empedia_Cloud_Client::request( 'DELETE', '/sso', null, true, 10 );
		}
		delete_option( self::OPTION );
	}

	public static function render_card() {
		$s = self::settings();
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Sign in with EMPEDIAcloud', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Members of your EMPEDIAcloud organization (and of your agency) can sign in here with their EMPEDIAcloud account, including its passkeys. Nobody gets an account automatically: a user must already exist on this site with the same, verified e-mail address. The password sign-in stays available.', 'empedia-shield' ) . '</p>';
		if ( self::off() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Signing in with EMPEDIAcloud is switched off by wp-config.php.', 'empedia-shield' ) . '</p></div>';
		}
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			echo '<p class="description">' . esc_html__( 'Connect this site to EMPEDIAcloud first.', 'empedia-shield' ) . '</p></div>';
			return;
		}
		echo '<p><strong>' . esc_html( $s['enabled'] ? __( 'On', 'empedia-shield' ) : __( 'Off', 'empedia-shield' ) ) . '</strong></p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="' . esc_attr( $s['enabled'] ? 'empedia_cloud_sso_disable' : 'empedia_cloud_sso_enable' ) . '">';
		wp_nonce_field( $s['enabled'] ? 'empedia_cloud_sso_disable' : 'empedia_cloud_sso_enable' );
		echo '<button type="submit" class="button ' . ( $s['enabled'] ? '' : 'button-primary' ) . '">' . esc_html( $s['enabled'] ? __( 'Turn off', 'empedia-shield' ) : __( 'Turn on', 'empedia-shield' ) ) . '</button></form>';
		echo '<p class="description" style="margin-top:10px">' . esc_html__( 'Emergency exit: add define( \'EMPEDIA_CLOUD_SSO_OFF\', true ); to wp-config.php.', 'empedia-shield' ) . '</p></div>';
	}
}
