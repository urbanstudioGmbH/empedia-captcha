<?php
/**
 * Bootstrap: schedules, domain verification file, sending the inventory, cached status.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Plugin {

	const STATUS_TRANSIENT = 'empedia_cloud_status';
	const STATUS_LAST      = 'empedia_cloud_status_last';
	const HOOK_INVENTORY   = 'empedia_cloud_inventory';
	const HOOK_HEARTBEAT   = 'empedia_cloud_heartbeat';
	const HOOK_VERIFY      = 'empedia_cloud_verify_retry';

	public static function init() {
		add_action( 'plugins_loaded', array( __CLASS__, 'load_textdomain' ) );
		add_action( 'plugins_loaded', array( 'Empedia_Cloud_Hardening', 'bootstrap' ), 20 );
		add_action( 'init', array( __CLASS__, 'serve_verification_file' ), 0 );
		add_action( 'admin_init', array( __CLASS__, 'privacy_policy_content' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
		add_action( self::HOOK_INVENTORY, array( __CLASS__, 'cron_inventory' ) );
		add_action( self::HOOK_HEARTBEAT, array( __CLASS__, 'cron_heartbeat' ) );
		add_action( self::HOOK_VERIFY, array( __CLASS__, 'cron_verify' ) );

		// Changes that matter for the inventory: send it soon after (once, not on every change).
		foreach ( array( 'activated_plugin', 'deactivated_plugin', 'deleted_plugin', 'upgrader_process_complete', 'switch_theme', '_core_updated_successfully', 'empedia_cloud_backup_done', 'empedia_cloud_backup_failed', 'empedia_cloud_restore_done', 'empedia_cloud_restore_failed' ) as $hook ) {
			add_action( $hook, array( __CLASS__, 'schedule_soon' ) );
		}

		Empedia_Cloud_Protect::init();
		Empedia_Cloud_Sso::init();
		Empedia_Cloud_Scanner::init();
		Empedia_Cloud_Watch::init();
		Empedia_Cloud_Comments::init();
		Empedia_Cloud_Backup::init();
		Empedia_Cloud_Restore::init();
		if ( is_admin() ) {
			Empedia_Cloud_Comments::init_admin();
			Empedia_Cloud_Admin::init();
			Empedia_Cloud_Protect_Admin::init();
			Empedia_Cloud_Sso::register_admin();
			Empedia_Cloud_Bots::init();
			Empedia_Cloud_Files_Admin::init();
			Empedia_Cloud_Backup_Admin::init();
			Empedia_Cloud_Firewall_Admin::init();
		}
	}

	/**
	 * Suggested text for the privacy policy of the site (Settings → Privacy → Policy Guide).
	 */
	public static function privacy_policy_content() {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$paragraphs = array(
			__( 'EMPEDIA Shield protects this site locally (sign-in protection, file check, firewall, backups). Without a connection to EMPEDIAcloud nothing is sent to the plugin author. The firewall stores only counters per rule and day and a few samples without IP addresses; sign-in protection stores failed-attempt counters and, with the optional second factor, the factors of each user in the site database.', 'empedia-shield' ),
			__( 'If you connect the site to EMPEDIAcloud (urbanstudio GmbH, Germany, https://empedia.cloud), the plugin sends a technical inventory: WordPress, PHP and database versions, the list of plugins and themes with versions, security settings, file check results (paths and rule names, no file contents) and the number of administrators. It does not send names, e-mail addresses or content. EMPEDIAcloud also reaches the public site to check availability and to scan it.', 'empedia-shield' ),
			__( 'Optional services: bot protection (EMPEDIAcaptcha) sends the check token and, with the content check, the text of a form entry and the visitor IP address to the configured service address; backups can be stored on your own storage target or at EMPEDIAcloud backup storage (encrypted on this site before they leave it). Please describe the services you switch on, and name the bot protection service in the section about forms and comments.', 'empedia-shield' ),
		);
		wp_add_privacy_policy_content( 'EMPEDIA Shield', wp_kses_post( wpautop( implode( "\n\n", $paragraphs ) ) ) );
	}

	public static function load_textdomain() {
		// phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound -- the plugin ships its own German files until translate.wordpress.org language packs cover it.
		load_plugin_textdomain( 'empedia-shield', false, dirname( plugin_basename( EMPEDIA_CLOUD_FILE ) ) . '/languages' );
	}

	public static function activate() {
		delete_option( 'empedia_plugins_auto_update' ); // setting of the former self-updater ( updates now come from wordpress.org )
		// Someone who installed the early firewall loader of the former plugin keeps the early start: replace it by the new one.
		if ( Empedia_Cloud_Firewall::mu_legacy_installed() ) {
			Empedia_Cloud_Firewall::install_mu();
		}
		// Nothing is sent before the site is connected.
		if ( Empedia_Cloud_Client::is_connected() ) {
			self::ensure_schedule();
		}
	}

	public static function deactivate() {
		self::clear_schedule();
		Empedia_Cloud_Scanner::clear_schedule();
		wp_clear_scheduled_hook( Empedia_Cloud_Watch::HOOK_SEND );
		Empedia_Cloud_Firewall::remove_mu(); // the early loader must not outlive the plugin
	}

	/** Called right after a successful connection. */
	public static function after_connect() {
		self::clear_schedule();
		self::ensure_schedule();
		update_option( 'empedia_cloud_verify_try', 0, false );
		wp_schedule_single_event( time() + 5, self::HOOK_INVENTORY );
		if ( get_option( 'empedia_cloud_verify' ) ) {
			wp_schedule_single_event( time() + 20, self::HOOK_VERIFY );
		}
	}

	public static function ensure_schedule() {
		if ( ! Empedia_Cloud_Client::is_connected() || get_option( 'empedia_cloud_token_invalid' ) ) {
			return;
		}
		if ( ! wp_next_scheduled( self::HOOK_INVENTORY ) ) {
			wp_schedule_event( time() + 120, 'daily', self::HOOK_INVENTORY );
		}
		if ( ! wp_next_scheduled( self::HOOK_HEARTBEAT ) ) {
			wp_schedule_event( time() + 300, 'hourly', self::HOOK_HEARTBEAT );
		}
	}

	public static function clear_schedule() {
		foreach ( array( self::HOOK_INVENTORY, self::HOOK_HEARTBEAT, self::HOOK_VERIFY ) as $h ) {
			wp_clear_scheduled_hook( $h );
		}
	}

	/** One extra inventory run in about a minute (not scheduled again while one is pending). */
	public static function schedule_soon() {
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			return;
		}
		$next = wp_next_scheduled( self::HOOK_INVENTORY );
		if ( ! $next || $next - time() > 600 ) {
			wp_schedule_single_event( time() + 60, self::HOOK_INVENTORY );
		}
	}

	/** Serves /.well-known/empedia-<token>.txt – the cloud's proof that this domain belongs to the connected account. */
	public static function serve_verification_file() {
		$v = get_option( 'empedia_cloud_verify' );
		if ( ! is_array( $v ) || empty( $v['path'] ) || empty( $v['content'] ) || empty( $_SERVER['REQUEST_URI'] ) ) {
			return;
		}
		$path = wp_parse_url( wp_unslash( $_SERVER['REQUEST_URI'] ), PHP_URL_PATH ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( $path === $v['path'] ) {
			status_header( 200 );
			nocache_headers();
			header( 'Content-Type: text/plain; charset=utf-8' );
			echo esc_html( $v['content'] );
			exit;
		}
	}

	/** Daily and on changes: send the inventory. */
	public static function cron_inventory() {
		update_option( 'empedia_cloud_cron_seen', time(), false );
		Empedia_Cloud_Atomic::cleanup();
		Empedia_Cloud_Firewall::cleanup();
		self::send_inventory( true );
	}

	public static function cron_heartbeat() {
		update_option( 'empedia_cloud_cron_seen', time(), false );
		if ( Empedia_Cloud_Client::is_connected() ) {
			$r = Empedia_Cloud_Client::request( 'POST', '/heartbeat', array( 'backup' => Empedia_Cloud_Backup_Report::summary() ), true, 10 );
			if ( ! is_wp_error( $r ) ) {
				Empedia_Cloud_Firewall::apply_remote( $r ); // emergency switch of the firewall
			}
		}
	}

	/** Checks the domain proof with the cloud; retries with growing pauses until it works. */
	public static function cron_verify() {
		if ( ! Empedia_Cloud_Client::is_connected() || ! get_option( 'empedia_cloud_verify' ) ) {
			return;
		}
		$r = self::verify_now();
		if ( true === $r ) {
			return;
		}
		$try   = (int) get_option( 'empedia_cloud_verify_try', 0 ) + 1;
		$waits = array( 300, 1800, 7200, 43200, 86400 );
		update_option( 'empedia_cloud_verify_try', $try, false );
		if ( $try <= count( $waits ) ) {
			wp_schedule_single_event( time() + $waits[ $try - 1 ], self::HOOK_VERIFY );
		}
	}

	/** @return true|false|WP_Error true = verified. */
	public static function verify_now() {
		$r = Empedia_Cloud_Client::request( 'POST', '/verify', array(), true, 25 );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( ! empty( $r['verified'] ) ) {
			$c             = Empedia_Cloud_Client::conn();
			$c['verified'] = true;
			Empedia_Cloud_Client::save_conn( $c );
			delete_option( 'empedia_cloud_verify' );
			delete_transient( self::STATUS_TRANSIENT );
			return true;
		}
		return false;
	}

	/**
	 * Sends the inventory.
	 *
	 * @param bool|string[] $probes true = all measurements, false = reuse the last ones, array = only these.
	 * @return array|WP_Error
	 */
	public static function send_inventory( $probes = true ) {
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			return new WP_Error( 'empedia_not_connected', __( 'This site is not connected to EMPEDIAcloud.', 'empedia-shield' ) );
		}
		$r = Empedia_Cloud_Client::request( 'POST', '/inventory', Empedia_Cloud_Inventory::collect( $probes ), true, 25 );
		if ( ! is_wp_error( $r ) ) {
			Empedia_Cloud_Firewall::apply_remote( $r );
			update_option( 'empedia_cloud_last_sync', time(), false );
			delete_transient( self::STATUS_TRANSIENT );
		}
		return $r;
	}

	/**
	 * Status from the cloud, cached for five minutes. The last good answer is kept to show something when the cloud is unreachable.
	 *
	 * @return array|WP_Error
	 */
	public static function get_status( $force = false ) {
		$lang = Empedia_Cloud_Client::lang();
		if ( ! $force ) {
			$c = get_transient( self::STATUS_TRANSIENT );
			if ( is_array( $c ) && isset( $c['_lang'] ) && $c['_lang'] === $lang ) {
				return $c;
			}
			$e = get_transient( 'empedia_cloud_status_err' );
			if ( $e ) {
				return new WP_Error( 'empedia_http', (string) $e ); // do not wait for an unreachable cloud on every reload
			}
		}
		$r = Empedia_Cloud_Client::request( 'GET', '/status?lang=' . rawurlencode( $lang ), null, true, 12 );
		if ( is_wp_error( $r ) ) {
			set_transient( 'empedia_cloud_status_err', $r->get_error_message(), 60 );
			return $r;
		}
		delete_transient( 'empedia_cloud_status_err' );
		$r['_lang'] = $lang;
		set_transient( self::STATUS_TRANSIENT, $r, 5 * MINUTE_IN_SECONDS );
		update_option( self::STATUS_LAST, array( 'at' => time(), 'status' => $r ), false );
		return $r;
	}

	/** Last good status ( for the dashboard widget and when the cloud is unreachable ) or null. */
	public static function last_status() {
		$l = get_option( self::STATUS_LAST );
		return is_array( $l ) && isset( $l['status'] ) ? $l : null;
	}
}
