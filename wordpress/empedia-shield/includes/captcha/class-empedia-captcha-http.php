<?php
/**
 * HTTP transport of the bot-protection module: all requests to the EMPEDIAcaptcha service go through the WordPress HTTP API
 * (wp_remote_request), so proxies, SSL settings and the WP_HTTP_BLOCK_EXTERNAL rules of the site apply.
 * It is handed to the SDK client (lib/empedia-captcha/Client.php, option "transport").
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Empedia_Captcha_Http', false ) ) {

	/**
	 * Transport for the SDK client and the page gate.
	 */
	final class Empedia_Captcha_Http {

		/**
		 * Sends one request.
		 *
		 * @param string      $method  GET or POST.
		 * @param string      $url     Full address.
		 * @param string|null $body    Request body (POST).
		 * @param string[]    $headers Header lines like "Content-Type: application/json".
		 * @param float       $timeout Seconds.
		 * @return string|null Response body of any status code, or null when the service could not be reached.
		 */
		public static function send( $method, $url, $body, array $headers, $timeout ) {
			$res = self::request( $method, $url, $body, $headers, $timeout );
			return null === $res ? null : $res['body'];
		}

		/**
		 * Like send(), but with the status code (the page gate accepts 2xx only).
		 *
		 * @param string      $method  GET or POST.
		 * @param string      $url     Full address.
		 * @param string|null $body    Request body (POST).
		 * @param string[]    $headers Header lines.
		 * @param float       $timeout Seconds.
		 * @return array|null array( 'code' => int, 'body' => string ) or null on a connection error.
		 */
		public static function request( $method, $url, $body, array $headers, $timeout ) {
			$h = array();
			foreach ( $headers as $line ) {
				$pos = strpos( (string) $line, ':' );
				if ( false !== $pos ) {
					$h[ trim( substr( $line, 0, $pos ) ) ] = trim( substr( $line, $pos + 1 ) );
				}
			}
			$args = array(
				'method'      => 'POST' === $method ? 'POST' : 'GET',
				'timeout'     => max( 1, (float) $timeout ),
				'redirection' => 0,
				'headers'     => $h,
				'user-agent'  => 'EMPEDIA-Shield/' . ( defined( 'EMPEDIA_CLOUD_VERSION' ) ? EMPEDIA_CLOUD_VERSION : '1' ) . '; ' . home_url(),
			);
			if ( null !== $body ) {
				$args['body'] = $body;
			}
			$res = wp_remote_request( $url, $args );
			if ( is_wp_error( $res ) ) {
				return null;
			}
			return array(
				'code' => (int) wp_remote_retrieve_response_code( $res ),
				'body' => (string) wp_remote_retrieve_body( $res ),
			);
		}
	}
}
