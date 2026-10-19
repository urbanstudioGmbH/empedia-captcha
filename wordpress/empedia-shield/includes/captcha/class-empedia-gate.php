<?php
/**
 * Page gate (pre-check) of the bot-protection module, WordPress edition.
 *
 * Visitors without a valid pass are sent to the check page of the EMPEDIAcaptcha service for a moment and come back; this class verifies
 * the token (siteverify) and sets its own signed cookie ("empedia_pass", strictly necessary). Same behaviour as the stand-alone module
 * for other PHP sites (frontend/captcha/v1/modules/empedia-gate.php in the source repository), but built on the WordPress APIs:
 * wp_remote_*, transients instead of temporary files, wp_redirect, status_header.
 *
 * Fail-open: when the service cannot be reached, every visitor passes. Search engines (reverse DNS check) and exception paths pass.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Empedia_Captcha_Gate', false ) ) {

	/**
	 * The gate.
	 */
	final class Empedia_Captcha_Gate {

		const CFG_TTL = 60;

		/** @var array Settings of the plugin: base, sitekey, secret. */
		private $o;

		/**
		 * Runs the gate (called early on plugins_loaded, never for admin, login, cron, REST, Ajax, CLI or signed-in people).
		 *
		 * @param array $o Options of the module (base, sitekey, secret).
		 */
		public static function run( array $o ) {
			$gate = new self();
			$gate->o = $o;
			$gate->handle();
		}

		/**
		 * Raw server value, unslashed and reduced to plain text.
		 *
		 * @param string $key Key in $_SERVER.
		 * @param int    $max Maximum length.
		 * @return string
		 */
		private static function server( $key, $max = 2048 ) {
			return isset( $_SERVER[ $key ] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER[ $key ] ) ), 0, $max ) : '';
		}

		/**
		 * Is the proxy set-up trusted for X-Forwarded-* (constant or environment variable EMPEDIA_TRUST_PROXY = 1)?
		 *
		 * @return bool
		 */
		private static function trust_proxy() {
			$v = defined( 'EMPEDIA_TRUST_PROXY' ) ? (string) EMPEDIA_TRUST_PROXY : (string) getenv( 'EMPEDIA_TRUST_PROXY' );
			return '1' === $v;
		}

		/**
		 * GET or POST to the service: body of a 2xx answer, otherwise null.
		 *
		 * @param string     $url  Address.
		 * @param array|null $post Form fields for a POST.
		 * @return string|null
		 */
		private static function http( $url, $post = null ) {
			$res = Empedia_Captcha_Http::request(
				null !== $post ? 'POST' : 'GET',
				$url,
				null !== $post ? http_build_query( $post ) : null,
				null !== $post ? array( 'Content-Type: application/x-www-form-urlencoded' ) : array(),
				4
			);
			return ( null !== $res && $res['code'] >= 200 && $res['code'] < 300 ) ? $res['body'] : null;
		}

		/**
		 * Settings of the gate from the service (cached for a minute; if the service is down, the last known settings stay in use).
		 *
		 * @return array|null
		 */
		private function config() {
			$key = 'empedia_gate_cfg_' . md5( $this->o['base'] . $this->o['sitekey'] );
			$c   = get_transient( $key );
			if ( is_array( $c ) ) {
				return $c;
			}
			$raw = self::http( $this->o['base'] . '/captcha/v1/gate-config?sitekey=' . rawurlencode( $this->o['sitekey'] ) );
			$c   = null !== $raw ? json_decode( $raw, true ) : null;
			if ( is_array( $c ) && array_key_exists( 'enabled', $c ) ) {
				set_transient( $key, $c, self::CFG_TTL );
				update_option( $key . '_last', $c, false );
				return $c;
			}
			$old = get_option( $key . '_last', null );
			return is_array( $old ) ? $old : null;
		}

		/**
		 * URL-safe Base64.
		 *
		 * @param string $bin Binary.
		 * @return string
		 */
		private static function b64( $bin ) {
			return rtrim( strtr( base64_encode( $bin ), '+/', '-_' ), '=' ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- URL-safe encoding of an HMAC for the pass cookie, no obfuscation.
		}

		/**
		 * Signature of the pass cookie (expiry bound to the browser string).
		 *
		 * @param int $exp Expiry (Unix time).
		 * @return string
		 */
		private function sig( $exp ) {
			return self::b64( hash_hmac( 'sha256', $exp . '|' . self::server( 'HTTP_USER_AGENT', 200 ), $this->o['secret'], true ) );
		}

		/**
		 * Is the pass cookie valid?
		 *
		 * @return bool
		 */
		private function cookie_ok() {
			$v = isset( $_COOKIE['empedia_pass'] ) ? sanitize_text_field( wp_unslash( $_COOKIE['empedia_pass'] ) ) : '';
			if ( ! preg_match( '/^(\d{9,11})\.([A-Za-z0-9_-]{43})$/', $v, $m ) ) {
				return false;
			}
			return (int) $m[1] > time() && hash_equals( $this->sig( (int) $m[1] ), $m[2] );
		}

		/**
		 * HTTPS in front (or behind a trusted proxy)?
		 *
		 * @return bool
		 */
		private static function https() {
			if ( is_ssl() ) {
				return true;
			}
			return self::trust_proxy() && 'https' === strtolower( self::server( 'HTTP_X_FORWARDED_PROTO', 10 ) );
		}

		/**
		 * Address of the current request, optionally without the gate parameter.
		 *
		 * @param bool $without_gate Remove ?empedia_gate=… (for the way back).
		 * @return string
		 */
		private static function current_url( $without_gate = false ) {
			// esc_url_raw keeps %XX octets of a relative address (sanitize_text_field would remove them).
			$uri = isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/';
			$uri = '' === $uri ? '/' : $uri;
			if ( $without_gate ) {
				$parts = explode( '?', $uri, 2 );
				$qs    = isset( $parts[1] ) ? ltrim( (string) preg_replace( '/(^|&)empedia_gate=[^&]*/', '', $parts[1] ), '&' ) : '';
				$uri   = $parts[0] . ( '' !== $qs ? '?' . $qs : '' );
			}
			return ( self::https() ? 'https' : 'http' ) . '://' . self::server( 'HTTP_HOST', 255 ) . $uri;
		}

		/**
		 * Address of the visitor.
		 *
		 * @return string
		 */
		private static function client_ip() {
			if ( self::trust_proxy() && '' !== self::server( 'HTTP_X_FORWARDED_FOR' ) ) {
				return trim( explode( ',', self::server( 'HTTP_X_FORWARDED_FOR' ) )[0] );
			}
			return self::server( 'REMOTE_ADDR', 64 );
		}

		/**
		 * Search-engine robot: the reverse DNS name must end in a known domain and resolve forward to the same address (result kept for a day).
		 *
		 * @param array $cfg Settings of the gate (crawler_suffixes).
		 * @return bool
		 */
		private function is_crawler( array $cfg ) {
			$ip = self::client_ip();
			if ( '' === $ip || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return false;
			}
			$key    = 'empedia_gate_bot_' . md5( $ip );
			$cached = get_transient( $key );
			if ( false !== $cached ) {
				return '1' === $cached;
			}
			$ok   = false;
			$host = strtolower( (string) @gethostbyaddr( $ip ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- a failing DNS lookup only means "not a known robot".
			if ( '' !== $host && strtolower( $ip ) !== $host ) {
				foreach ( (array) ( isset( $cfg['crawler_suffixes'] ) ? $cfg['crawler_suffixes'] : array() ) as $suf ) {
					$suf = (string) $suf;
					if ( '' !== $suf && substr( $host, -strlen( $suf ) ) === $suf ) {
						if ( false !== strpos( $ip, ':' ) ) {
							$fwd = array_column( (array) @dns_get_record( $host, DNS_AAAA ), 'ipv6' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- see above.
						} else {
							$fwd = (array) @gethostbynamel( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- see above.
						}
						$ok = in_array( $ip, $fwd, true );
						break;
					}
				}
			}
			set_transient( $key, $ok ? '1' : '0', DAY_IN_SECONDS );
			return $ok;
		}

		/**
		 * Plain-text refusal (scripts, form posts and background calls without a pass, failed verification).
		 *
		 * @param string $text Message.
		 */
		private static function deny( $text ) {
			status_header( 403 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo esc_html( $text );
			exit;
		}

		/**
		 * The decision.
		 */
		private function handle() {
			$cfg = $this->config();
			if ( ! $cfg || empty( $cfg['enabled'] ) ) {
				return;
			}
			$method = self::server( 'REQUEST_METHOD', 10 );
			$path   = (string) wp_parse_url( self::current_url(), PHP_URL_PATH );
			$path   = '' === $path ? '/' : $path;
			foreach ( (array) ( isset( $cfg['skip'] ) ? $cfg['skip'] : array() ) as $p ) {
				if ( '' !== (string) $p && 0 === strpos( $path, (string) $p ) ) {
					return;
				}
			}

			// Way back from the check page: verify the token and issue the pass. The token is the credential itself (checked by the
			// service), there is no form of ours, so no nonce applies.
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- return from the external check page, verified server to server by siteverify.
			$token = isset( $_GET['empedia_gate'] ) && is_string( $_GET['empedia_gate'] ) ? preg_replace( '/[^A-Za-z0-9._-]/', '', sanitize_text_field( wp_unslash( $_GET['empedia_gate'] ) ) ) : '';
			if ( '' !== $token ) {
				$raw  = self::http(
					$this->o['base'] . '/captcha/v1/siteverify',
					array(
						'secret'   => $this->o['secret'],
						'response' => $token,
						'action'   => 'gate',
					)
				);
				$r    = null !== $raw ? json_decode( $raw, true ) : null;
				$host = strtolower( (string) preg_replace( '/:\d+$/', '', self::server( 'HTTP_HOST', 255 ) ) );
				if ( is_array( $r ) && true === ( isset( $r['success'] ) ? $r['success'] : false ) && strtolower( (string) ( isset( $r['hostname'] ) ? $r['hostname'] : '' ) ) === $host ) {
					$exp = time() + max( 5, (int) ( isset( $cfg['ttl_min'] ) ? $cfg['ttl_min'] : 60 ) ) * 60;
					setcookie(
						'empedia_pass',
						$exp . '.' . $this->sig( $exp ),
						array(
							'expires'  => $exp,
							'path'     => '/',
							'secure'   => self::https(),
							'httponly' => true,
							'samesite' => 'Lax',
						)
					);
					nocache_headers();
					wp_redirect( self::current_url( true ), 302, 'EMPEDIA Shield' ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the address is the visitor's own request on this site.
					exit;
				}
				self::deny( 'Verification failed.' ); // No new redirect: prevents loops.
			}

			if ( $this->cookie_ok() ) {
				return;
			}
			if ( ! empty( $cfg['crawlers'] ) && $this->is_crawler( $cfg ) ) {
				return;
			}

			$wants_html = in_array( $method, array( 'GET', 'HEAD' ), true ) && false !== stripos( self::server( 'HTTP_ACCEPT', 500 ), 'text/html' );
			if ( $wants_html ) {
				nocache_headers();
				wp_redirect( $this->o['base'] . '/captcha/v1/gate?sitekey=' . rawurlencode( $this->o['sitekey'] ) . '&return=' . rawurlencode( self::current_url() ), 302, 'EMPEDIA Shield' ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- the check page of the configured EMPEDIAcaptcha service.
				exit;
			}
			self::deny( 'Forbidden.' ); // Scripts, form posts and background calls without a pass.
		}
	}
}
