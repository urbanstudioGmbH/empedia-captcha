<?php
/**
 * Update check for this add-on, which is distributed from empedia.cloud instead of wordpress.org.
 * Same logic as the former update class of the EMPEDIA plugins: signed packages, SHA-256, https only.
 *
 * It asks GET <base>/api/public/plugin-updates/<slug> (no account, no site data – only the slug is part of the
 * request) at most every 12 hours and hands the answer to WordPress, so the normal update screen, bulk updates and
 * automatic updates work as usual.
 *
 * @package EmpediaShieldSftp
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Empedia_Plugin_Updater' ) ) {

	class Empedia_Plugin_Updater {

		/**
		 * Public keys ( base64, 32 bytes each, Ed25519, comma separated ) that may sign a release: the current one and, while a key is being
		 * rotated, the next one. Filled in by the server when it builds the package ( PLUGIN_SIGNING_KEY / PLUGIN_TRUSTED_PUBKEYS ).
		 * While empty, packages are checked by their SHA-256 only.
		 */
		const PUBKEY = '';

		/** @var string Plugin basename, e.g. empedia-shield-sftp/empedia-shield-sftp.php */
		private $basename;
		private $slug;
		private $version;
		private $base;

		/** @var array<string,string> basename => slug of every registered plugin ( shared if several are registered ). */
		private static $registered = array();

		/** Option: '0' switches automatic installation of our updates off ( default: on ). */
		const OPT_AUTO = 'empedia_sftp_auto_update';

		/**
		 * @param string $file    Main plugin file ( __FILE__ ).
		 * @param string $version Installed version.
		 * @param string $base    Cloud address without trailing slash.
		 */
		public static function register( $file, $version, $base ) {
			$u           = new self();
			$u->basename = plugin_basename( $file );
			$u->slug     = dirname( $u->basename );
			$u->version  = $version;
			$u->base     = untrailingslashit( $base );
			add_filter( 'pre_set_site_transient_update_plugins', array( $u, 'inject' ) );
			add_filter( 'plugins_api', array( $u, 'info' ), 20, 3 );
			add_filter( 'upgrader_pre_download', array( $u, 'pre_download' ), 10, 3 );
			add_action( 'upgrader_process_complete', array( $u, 'forget' ), 10, 2 );
			add_filter( 'auto_update_plugin', array( $u, 'auto' ), 20, 2 );
			if ( empty( self::$registered ) ) {
				add_action( 'admin_notices', array( __CLASS__, 'notice' ) );
				add_action( 'admin_post_empedia_plugins_check', array( __CLASS__, 'handle_check' ) );
			}
			self::$registered[ $u->basename ] = $u->slug;
		}

		/** Are automatic updates of our plugins wanted? ( constant EMPEDIA_SHIELD_SFTP_AUTO_UPDATE = false or the option switch them off ) */
		public static function auto_enabled() {
			if ( defined( 'EMPEDIA_SHIELD_SFTP_AUTO_UPDATE' ) && ! EMPEDIA_SHIELD_SFTP_AUTO_UPDATE ) {
				return false;
			}
			return '0' !== (string) get_option( self::OPT_AUTO, '1' );
		}

		/** WordPress asks per plugin whether to install an update by itself; packages are still verified before installation ( pre_download ). */
		public function auto( $update, $item ) {
			if ( is_object( $item ) && isset( $item->plugin ) && $item->plugin === $this->basename ) {
				return self::auto_enabled();
			}
			return $update;
		}

		/** @return array<int,array{basename:string,slug:string,name:string,installed:string,latest:string}> Updates WordPress knows about for our plugins. */
		public static function pending() {
			$t   = get_site_transient( 'update_plugins' );
			$out = array();
			if ( ! is_object( $t ) || empty( $t->response ) ) {
				return $out;
			}
			if ( ! function_exists( 'get_plugin_data' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			foreach ( self::$registered as $basename => $slug ) {
				if ( isset( $t->response[ $basename ] ) ) {
					$data  = get_plugin_data( WP_PLUGIN_DIR . '/' . $basename, false, false );
					$out[] = array(
						'basename'  => $basename,
						'slug'      => $slug,
						'name'      => ! empty( $data['Name'] ) ? $data['Name'] : $slug,
						'installed' => ! empty( $data['Version'] ) ? $data['Version'] : '',
						'latest'    => (string) $t->response[ $basename ]->new_version,
					);
				}
			}
			return $out;
		}

		/** Drops our cached answers and asks WordPress to look again right now. */
		public static function check_now() {
			foreach ( self::$registered as $slug ) {
				delete_site_transient( 'empedia_upd_' . md5( $slug ) );
			}
			if ( ! function_exists( 'wp_update_plugins' ) ) {
				require_once ABSPATH . 'wp-includes/update.php';
			}
			delete_site_transient( 'update_plugins' );
			wp_update_plugins();
		}

		public static function handle_check() {
			if ( ! current_user_can( 'update_plugins' ) ) {
				wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield-sftp' ), '', array( 'response' => 403 ) );
			}
			check_admin_referer( 'empedia_plugins_check' );
			self::check_now();
			$back = wp_get_referer();
			wp_safe_redirect( $back ? $back : admin_url( 'plugins.php' ) );
			exit;
		}

		/** Notice on the admin screens: a newer version of one of our plugins exists. */
		public static function notice() {
			if ( ! current_user_can( 'update_plugins' ) ) {
				return;
			}
			$screen = function_exists( 'get_current_screen' ) ? get_current_screen() : null;
			if ( $screen && in_array( $screen->id, array( 'update-core', 'plugin-install' ), true ) ) {
				return;
			}
			foreach ( self::pending() as $p ) {
				$url = wp_nonce_url( self_admin_url( 'update.php?action=upgrade-plugin&plugin=' . rawurlencode( $p['basename'] ) ), 'upgrade-plugin_' . $p['basename'] );
				printf(
					'<div class="notice notice-warning"><p><strong>%1$s</strong> %2$s <a href="%3$s" class="button button-primary" style="margin-left:8px">%4$s</a></p></div>',
					esc_html( $p['name'] ),
					esc_html(
						sprintf(
							/* translators: 1: installed version, 2: new version */
							__( 'is out of date: version %1$s is installed, version %2$s is available.', 'empedia-shield-sftp' ),
							'' !== $p['installed'] ? $p['installed'] : '?',
							$p['latest']
						) . ' ' . ( self::auto_enabled() ? __( 'It will be installed automatically with the next WordPress update run.', 'empedia-shield-sftp' ) : __( 'Automatic updates are switched off.', 'empedia-shield-sftp' ) )
					),
					esc_url( $url ),
					esc_html__( 'Update now', 'empedia-shield-sftp' )
				);
			}
		}

		private function key() {
			return 'empedia_upd_' . md5( $this->slug );
		}

		/** Latest release data or null ( cached 12 h, a failed request is cached for 1 h ). */
		private function remote() {
			$c = get_site_transient( $this->key() );
			if ( is_array( $c ) ) {
				return empty( $c['version'] ) ? null : $c;
			}
			$res  = wp_remote_get( $this->base . '/api/public/plugin-updates/' . rawurlencode( $this->slug ), array( 'timeout' => 8, 'headers' => array( 'Accept' => 'application/json' ) ) );
			$code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
			$d    = 200 === $code ? json_decode( wp_remote_retrieve_body( $res ), true ) : null;
			if ( ! is_array( $d ) || empty( $d['version'] ) || ! preg_match( '/^\d+(\.\d+){1,3}$/', (string) $d['version'] ) || empty( $d['download_url'] ) ) {
				set_site_transient( $this->key(), array( 'version' => '' ), HOUR_IN_SECONDS );
				return null;
			}
			// The package must come from the same host as the update information.
			$bh = wp_parse_url( $this->base, PHP_URL_HOST );
			$ph = wp_parse_url( (string) $d['download_url'], PHP_URL_HOST );
			if ( ! $bh || ! $ph || strtolower( $bh ) !== strtolower( $ph ) ) {
				set_site_transient( $this->key(), array( 'version' => '' ), HOUR_IN_SECONDS );
				return null;
			}
			set_site_transient( $this->key(), $d, 12 * HOUR_IN_SECONDS );
			return $d;
		}

		public function inject( $transient ) {
			if ( ! is_object( $transient ) ) {
				return $transient;
			}
			$d = $this->remote();
			if ( ! $d ) {
				return $transient;
			}
			$item = (object) array(
				'id'           => $this->base . '/' . $this->slug,
				'slug'         => $this->slug,
				'plugin'       => $this->basename,
				'new_version'  => $d['version'],
				'url'          => isset( $d['homepage'] ) ? esc_url_raw( $d['homepage'] ) : $this->base,
				'package'      => esc_url_raw( $d['download_url'] ),
				'requires'     => isset( $d['requires'] ) ? $d['requires'] : '',
				'requires_php' => isset( $d['requires_php'] ) ? $d['requires_php'] : '',
				'tested'       => isset( $d['tested'] ) ? $d['tested'] : '',
			);
			$icons = $this->icons( $d );
			if ( $icons ) {
				$item->icons = $icons;
			}
			if ( version_compare( $this->version, $d['version'], '<' ) ) {
				$transient->response[ $this->basename ] = $item;
				unset( $transient->no_update[ $this->basename ] );
			} else {
				$transient->no_update[ $this->basename ] = $item;
				unset( $transient->response[ $this->basename ] );
			}
			return $transient;
		}

		/** Data for the “View details” window. */
		public function info( $result, $action, $args ) {
			if ( 'plugin_information' !== $action || empty( $args->slug ) || $args->slug !== $this->slug ) {
				return $result;
			}
			$d = $this->remote();
			if ( ! $d ) {
				return $result;
			}
			$log = isset( $d['changelog'] ) ? (string) $d['changelog'] : '';
			return (object) array(
				'name'          => isset( $d['name'] ) ? $d['name'] : $this->slug,
				'slug'          => $this->slug,
				'version'       => $d['version'],
				'requires'      => isset( $d['requires'] ) ? $d['requires'] : '',
				'requires_php'  => isset( $d['requires_php'] ) ? $d['requires_php'] : '',
				'tested'        => isset( $d['tested'] ) ? $d['tested'] : '',
				'homepage'      => isset( $d['homepage'] ) ? esc_url_raw( $d['homepage'] ) : $this->base,
				'author'        => '<a href="https://urbanstudio.de">urbanstudio GmbH</a>',
				'download_link' => esc_url_raw( $d['download_url'] ),
				'sections'      => array( 'changelog' => '' === $log ? '' : '<pre>' . esc_html( $log ) . '</pre>' ),
				'icons'         => $this->icons( $d ),
			);
		}

		/** Icon addresses from the update data: only addresses on the cloud host itself are accepted. */
		private function icons( $d ) {
			$out = array();
			if ( empty( $d['icons'] ) || ! is_array( $d['icons'] ) ) {
				return $out;
			}
			foreach ( array( '1x', '2x' ) as $k ) {
				if ( ! empty( $d['icons'][ $k ] ) && is_string( $d['icons'][ $k ] ) ) {
					$u = esc_url_raw( $d['icons'][ $k ] );
					if ( $u && wp_parse_url( $u, PHP_URL_HOST ) === wp_parse_url( $this->base, PHP_URL_HOST ) ) {
						$out[ $k ] = $u;
					}
				}
			}
			return $out;
		}

		/**
		 * Downloads a package of ours itself and checks hash and signature before WordPress installs it.
		 * Anything else is left to WordPress.
		 */
		public function pre_download( $reply, $package, $upgrader ) {
			if ( ! is_string( $package ) || false === strpos( $package, '/api/public/plugin-updates/' . $this->slug . '/download' ) ) {
				return $reply;
			}
			$bh = wp_parse_url( $this->base, PHP_URL_HOST );
			$ph = wp_parse_url( $package, PHP_URL_HOST );
			if ( ! $bh || ! $ph || strtolower( $bh ) !== strtolower( $ph ) ) {
				return $reply;
			}
			return self::fetch_verified( $this->base, $this->slug, $this->version );
		}

		/** Does the host of the cloud allow plain http ( local tests only )? */
		private static function https_ok( $base ) {
			$p = wp_parse_url( $base );
			if ( empty( $p['scheme'] ) || empty( $p['host'] ) ) {
				return false;
			}
			return 'https' === $p['scheme'] || ( defined( 'EMPEDIA_SHIELD_SFTP_ALLOW_HTTP' ) && EMPEDIA_SHIELD_SFTP_ALLOW_HTTP );
		}

		/**
		 * Fetches the current release information and package, checks SHA-256 ( and the signature when a public key is built in ).
		 *
		 * @return string|WP_Error Path of the verified ZIP file.
		 */
		public static function fetch_verified( $base, $slug, $installed = '0' ) {
			$base = untrailingslashit( $base );
			$bad  = new WP_Error( 'empedia_package', __( 'The update package could not be verified and was not installed.', 'empedia-shield-sftp' ) );
			if ( ! self::https_ok( $base ) ) {
				return $bad;
			}
			$res  = wp_remote_get( $base . '/api/public/plugin-updates/' . rawurlencode( $slug ), array( 'timeout' => 10, 'headers' => array( 'Accept' => 'application/json' ) ) );
			$info = is_wp_error( $res ) || 200 !== (int) wp_remote_retrieve_response_code( $res ) ? null : json_decode( wp_remote_retrieve_body( $res ), true );
			if ( ! is_array( $info ) || empty( $info['download_url'] ) || empty( $info['sha256'] ) || empty( $info['version'] ) || ! preg_match( '/^[0-9a-f]{64}$/', (string) $info['sha256'] ) ) {
				return $bad;
			}
			$bh = wp_parse_url( $base, PHP_URL_HOST );
			$ph = wp_parse_url( (string) $info['download_url'], PHP_URL_HOST );
			if ( ! $bh || ! $ph || strtolower( $bh ) !== strtolower( $ph ) ) {
				return $bad;
			}
			// No downgrades: an older package ( even a correctly signed one ) is not installed over a newer version.
			if ( version_compare( (string) $info['version'], (string) $installed, '<' ) ) {
				return $bad;
			}
			if ( '' !== self::PUBKEY ) {
				$sig = isset( $info['signature'] ) ? base64_decode( (string) $info['signature'], true ) : false;
				$ok  = false;
				if ( function_exists( 'sodium_crypto_sign_verify_detached' ) && false !== $sig && 64 === strlen( $sig ) ) {
					foreach ( explode( ',', self::PUBKEY ) as $b64 ) {
						$pk = base64_decode( trim( $b64 ), true );
						if ( false !== $pk && 32 === strlen( $pk ) && sodium_crypto_sign_verify_detached( $sig, $slug . ':' . $info['version'] . ':' . $info['sha256'], $pk ) ) {
							$ok = true;
							break;
						}
					}
				}
				if ( ! $ok ) {
					return $bad;
				}
			}
			if ( ! function_exists( 'download_url' ) ) {
				require_once ABSPATH . 'wp-admin/includes/file.php';
			}
			$tmp = download_url( esc_url_raw( $info['download_url'] ), 60 );
			if ( is_wp_error( $tmp ) ) {
				return $tmp;
			}
			if ( ! hash_equals( (string) $info['sha256'], (string) hash_file( 'sha256', $tmp ) ) ) {
				@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
				return $bad;
			}
			return $tmp;
		}

		public function forget( $upgrader, $extra ) {
			if ( isset( $extra['type'] ) && 'plugin' === $extra['type'] ) {
				delete_site_transient( $this->key() );
			}
		}
	}
}
