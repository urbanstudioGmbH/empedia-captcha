<?php
/**
 * HTTP client for the EMPEDIAcloud API. Only technical data about this site is sent; the access token belongs to this
 * installation and can only use the plugin interface (/api/wp-site/*).
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Client {

	const OPTION = 'empedia_cloud_conn';

	/** Base address of the cloud (can be overridden with the constant EMPEDIA_CLOUD_URL or the filter). */
	public static function base() {
		$url = defined( 'EMPEDIA_CLOUD_URL' ) ? EMPEDIA_CLOUD_URL : 'https://empedia.cloud';
		$url = apply_filters( 'empedia_cloud_url', $url );
		return untrailingslashit( esc_url_raw( $url ) );
	}

	/** Stored connection ( token, installation_id, domain, … ) or an empty array. */
	public static function conn() {
		$c = get_option( self::OPTION, array() );
		return is_array( $c ) ? $c : array();
	}

	public static function is_connected() {
		$c = self::conn();
		return ! empty( $c['token'] );
	}

	public static function save_conn( array $conn ) {
		update_option( self::OPTION, $conn, false );
	}

	public static function clear_conn() {
		delete_option( self::OPTION );
	}

	/** Normalised address of this site as the cloud expects it (no trailing slash). */
	public static function site_url() {
		return untrailingslashit( home_url() );
	}

	/**
	 * Calls the API.
	 *
	 * @param string     $method GET|POST.
	 * @param string     $path   Path below /api/wp-site.
	 * @param array|null $body   JSON body.
	 * @param bool       $auth   Send the installation token.
	 * @param int        $timeout Seconds.
	 * @return array|WP_Error Decoded JSON on success.
	 */
	public static function request( $method, $path, $body = null, $auth = true, $timeout = 20 ) {
		$headers = array(
			'Accept'       => 'application/json',
			'Content-Type' => 'application/json',
			'User-Agent'   => 'EMPEDIAcloud-WordPress/' . EMPEDIA_CLOUD_VERSION . '; ' . self::site_url(),
		);
		if ( $auth ) {
			$c = self::conn();
			if ( empty( $c['token'] ) ) {
				return new WP_Error( 'empedia_not_connected', __( 'This site is not connected to EMPEDIAcloud.', 'empedia-shield' ) );
			}
			$headers['Authorization'] = 'Bearer ' . $c['token'];
		}
		$args = array(
			'method'      => $method,
			'timeout'     => $timeout,
			'redirection' => 0,
			'headers'     => $headers,
		);
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}
		$res = wp_remote_request( self::base() . '/api/wp-site' . $path, $args );
		if ( is_wp_error( $res ) ) {
			return new WP_Error( 'empedia_http', $res->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		$json = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( ! is_array( $json ) ) {
			$json = array();
		}
		if ( $code >= 400 || ( isset( $json['success'] ) && ! $json['success'] ) ) {
			$err = isset( $json['error'] ) ? sanitize_key( (string) $json['error'] ) : 'http_' . $code;
			if ( 401 === $code && $auth ) {
				// The token was revoked in the cloud: remember it so the settings page can say so.
				update_option( 'empedia_cloud_token_invalid', time(), false );
				Empedia_Cloud_Plugin::clear_schedule(); // stop reporting against a revoked token
			}
			$text = ( 'scan_failed' === $err && ! empty( $json['message'] ) ) ? sanitize_text_field( (string) $json['message'] ) : self::error_text( $err );
			return new WP_Error( 'empedia_' . $err, $text, array( 'status' => $code, 'data' => $json ) );
		}
		if ( $auth && get_option( 'empedia_cloud_token_invalid' ) ) {
			delete_option( 'empedia_cloud_token_invalid' );
		}
		return $json;
	}

	/** Human readable text for an error code of the cloud. */
	public static function error_text( $code ) {
		$map = array(
			'invalid_code'     => __( 'The code is invalid, expired or already used.', 'empedia-shield' ),
			'invalid_verifier' => __( 'The connection could not be confirmed. Please start again.', 'empedia-shield' ),
			'site_mismatch'    => __( 'The code was created for a different site.', 'empedia-shield' ),
			'site_limit'       => __( 'All site slots of your plan are in use. Disconnect a site or extend your plan.', 'empedia-shield' ),
			'domain_in_use'    => __( 'This domain is already connected to another WordPress installation.', 'empedia-shield' ),
			'https_required'   => __( 'The site must be reachable via https to connect.', 'empedia-shield' ),
			'invalid_site_url' => __( 'The address of this site is not valid for EMPEDIAcloud (no port numbers or credentials allowed).', 'empedia-shield' ),
			'invalid_token'    => __( 'The connection was ended in EMPEDIAcloud. Please connect again.', 'empedia-shield' ),
			'not_available'    => __( 'This feature is not available for your account yet.', 'empedia-shield' ),
			'domain_not_verified' => __( 'The domain is not verified yet.', 'empedia-shield' ),
			'scan_rate_limit'  => __( 'Several scans were already started in the last hour. Please try again later.', 'empedia-shield' ),
			'too_many_requests' => __( 'Too many requests. Please try again later.', 'empedia-shield' ),
			'captcha_unavailable' => __( 'Bot protection is not available for your account yet.', 'empedia-shield' ),
			'invalid_hosts'    => __( 'The domain could not be used for bot protection.', 'empedia-shield' ),
			'multiple_domains' => __( 'The domain could not be used for bot protection.', 'empedia-shield' ),
			'reauth_required'  => __( 'The connection was revoked or expired. Please connect the account again.', 'empedia-shield' ),
			'pro_required'     => __( 'This is part of the Pro plan of EMPEDIAcloud.', 'empedia-shield' ),
			'provider_not_configured' => __( 'This storage service is not available for your account yet.', 'empedia-shield' ),
			'invalid_callback' => __( 'The connection to the storage service failed.', 'empedia-shield' ),
			'token_exchange_failed' => __( 'The connection to the storage service failed.', 'empedia-shield' ),
			'site_inactive'    => __( 'This site is idle because all slots of your plan are in use.', 'empedia-shield' ),
		);
		return isset( $map[ $code ] ) ? $map[ $code ] : __( 'EMPEDIAcloud returned an error. Please try again later.', 'empedia-shield' );
	}

	/** Two-letter language of the current user/site for texts that the cloud renders. */
	public static function lang() {
		$l = strtolower( substr( (string) determine_locale(), 0, 2 ) );
		return in_array( $l, array( 'de', 'en', 'es', 'fr', 'it', 'pt', 'nl', 'pl', 'tr' ), true ) ? $l : 'en';
	}
}
