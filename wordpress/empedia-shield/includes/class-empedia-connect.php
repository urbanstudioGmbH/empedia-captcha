<?php
/**
 * Connecting this site with an EMPEDIAcloud account.
 *
 * Browser flow: the site opens the cloud with a PKCE challenge, the user signs in there and confirms; the cloud sends the
 * browser back to wp-admin with a one-time code, which this site exchanges together with the secret verifier for the
 * installation token. A connection code (ECW-…) created in the cloud can be typed in instead (for agencies).
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Connect {

	const PAGE = 'empedia-cloud';

	/** Settings page address (the cloud sends the browser back here). */
	public static function page_url( $args = array() ) {
		return add_query_arg( array_merge( array( 'page' => self::PAGE ), $args ), admin_url( 'admin.php' ) );
	}

	private static function b64url( $bin ) {
		return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions
	}

	/** Address in the cloud that starts the browser flow. Stores the secret verifier for 15 minutes. */
	public static function start_url() {
		$verifier  = self::b64url( random_bytes( 32 ) );
		$challenge = self::b64url( hash( 'sha256', $verifier, true ) );
		$state     = self::b64url( random_bytes( 12 ) );
		set_transient( 'empedia_cloud_pkce_' . $state, $verifier, 15 * MINUTE_IN_SECONDS );
		return Empedia_Cloud_Client::base() . '/wordpress-connect.html?' . http_build_query(
			array(
				'site'      => Empedia_Cloud_Client::site_url(),
				'challenge' => $challenge,
				'callback'  => self::page_url(),
				'state'     => $state,
			),
			'',
			'&',
			PHP_QUERY_RFC3986
		);
	}

	/**
	 * Called when the settings page opens with ?empedia_code=…&empedia_state=… (the cloud's redirect).
	 *
	 * @return true|WP_Error|null null when the request carries no code.
	 */
	public static function handle_return() {
		// phpcs:disable WordPress.Security.NonceVerification -- protected by the one-time state stored in a transient.
		if ( empty( $_GET['empedia_code'] ) || empty( $_GET['empedia_state'] ) ) {
			return null;
		}
		$code  = sanitize_text_field( wp_unslash( $_GET['empedia_code'] ) );
		$state = preg_replace( '/[^A-Za-z0-9_-]/', '', sanitize_text_field( wp_unslash( $_GET['empedia_state'] ) ) );
		// phpcs:enable
		$verifier = get_transient( 'empedia_cloud_pkce_' . $state );
		delete_transient( 'empedia_cloud_pkce_' . $state );
		if ( ! $verifier ) {
			return new WP_Error( 'empedia_state', __( 'The connection request expired. Please start again.', 'empedia-shield' ) );
		}
		return self::exchange( $code, $verifier );
	}

	/** Exchanges a code (browser flow with verifier, or connection code without) for the installation token and stores it. */
	public static function exchange( $code, $verifier = null ) {
		$body = array(
			'code'           => $code,
			'site_url'       => Empedia_Cloud_Client::site_url(),
			'plugin_version' => EMPEDIA_CLOUD_VERSION,
			'wp_version'     => get_bloginfo( 'version' ),
			'php_version'    => PHP_VERSION,
		);
		if ( $verifier ) {
			$body['verifier'] = $verifier;
		}
		$res = Empedia_Cloud_Client::request( 'POST', '/connect', $body, false );
		if ( is_wp_error( $res ) ) {
			return $res;
		}
		if ( empty( $res['token'] ) ) {
			return new WP_Error( 'empedia_bad_answer', __( 'EMPEDIAcloud returned an error. Please try again later.', 'empedia-shield' ) );
		}
		Empedia_Cloud_Client::save_conn(
			array(
				'token'           => (string) $res['token'],
				'installation_id' => isset( $res['installation_id'] ) ? (string) $res['installation_id'] : '',
				'domain'          => isset( $res['domain'] ) ? (string) $res['domain'] : '',
				'site_url'        => Empedia_Cloud_Client::site_url(),
				'connected_at'    => time(),
				'verified'        => ! empty( $res['verification']['verified'] ),
			)
		);
		delete_option( 'empedia_cloud_token_invalid' );
		delete_transient( Empedia_Cloud_Plugin::STATUS_TRANSIENT );
		// The cloud wants a file at /.well-known/empedia-<token>.txt as proof that the domain belongs to this site.
		$vf = isset( $res['verification']['file'] ) ? (string) $res['verification']['file'] : '';
		$vc = isset( $res['verification']['content'] ) ? (string) $res['verification']['content'] : '';
		if ( preg_match( '#^/\.well-known/empedia-[0-9a-f]{32}\.txt$#', $vf ) && preg_match( '/^empedia-verify=[0-9a-f]{32}$/', $vc ) ) {
			update_option(
				'empedia_cloud_verify',
				array(
					'path'    => $vf,
					'content' => $vc,
				),
				false
			);
		} else {
			delete_option( 'empedia_cloud_verify' );
		}
		Empedia_Cloud_Plugin::after_connect();
		return true;
	}

	/** Ends the connection: the cloud revokes the token (best effort), the local data is removed. */
	public static function disconnect() {
		if ( Empedia_Cloud_Client::is_connected() ) {
			Empedia_Cloud_Client::request( 'POST', '/disconnect', array(), true, 8 ); // also ends the sign-in app of this site in the cloud
		}
		delete_option( Empedia_Cloud_Sso::OPTION );
		Empedia_Cloud_Hardening::revert_all(); // without a connection the fixes could no longer be reverted from the settings page
		Empedia_Cloud_Client::clear_conn();
		delete_option( 'empedia_cloud_verify' );
		delete_option( 'empedia_cloud_token_invalid' );
		delete_transient( Empedia_Cloud_Plugin::STATUS_TRANSIENT );
		Empedia_Cloud_Plugin::clear_schedule();
	}
}
