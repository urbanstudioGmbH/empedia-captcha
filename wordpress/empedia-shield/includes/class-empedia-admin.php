<?php
/**
 * Admin page (main menu EMPEDIA Shield), dashboard widget and admin-post / AJAX handlers.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Admin {

	const CAP = 'manage_options';

	/** User meta: which upgrade notices a user closed ( key => timestamp ). */
	const DISMISS_META = 'empedia_cloud_dismissed';

	public static function init() {
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'notices' ) );
		add_action( 'load-toplevel_page_' . Empedia_Cloud_Connect::PAGE, array( __CLASS__, 'early_return' ) );
		add_action( 'wp_dashboard_setup', array( __CLASS__, 'dashboard_widget' ) );
		add_filter( 'plugin_action_links_' . plugin_basename( EMPEDIA_CLOUD_FILE ), array( __CLASS__, 'action_links' ) );
		foreach ( array( 'start', 'code', 'apply', 'revert', 'remeasure', 'refresh', 'verify', 'disconnect', 'dismiss' ) as $a ) {
			add_action( 'admin_post_empedia_cloud_' . $a, array( __CLASS__, 'handle_' . $a ) );
		}
		add_action( 'wp_ajax_empedia_cloud_scan_start', array( __CLASS__, 'ajax_scan_start' ) );
		add_action( 'wp_ajax_empedia_cloud_scan_poll', array( __CLASS__, 'ajax_scan_poll' ) );
	}

	public static function menu() {
		add_menu_page( __( 'EMPEDIA Shield', 'empedia-shield' ), __( 'EMPEDIA Shield', 'empedia-shield' ), self::CAP, Empedia_Cloud_Connect::PAGE, array( __CLASS__, 'render' ), 'dashicons-shield', 80 );
	}

	public static function action_links( $links ) {
		array_unshift( $links, '<a href="' . esc_url( Empedia_Cloud_Connect::page_url() ) . '">' . esc_html__( 'Settings', 'empedia-shield' ) . '</a>' );
		return $links;
	}

	public static function assets( $hook ) {
		if ( 'toplevel_page_' . Empedia_Cloud_Connect::PAGE !== $hook ) {
			return;
		}
		wp_enqueue_style( 'empedia-cloud-admin', EMPEDIA_CLOUD_URL_BASE . 'assets/admin.css', array(), EMPEDIA_CLOUD_VERSION );
		wp_enqueue_script( 'empedia-cloud-admin', EMPEDIA_CLOUD_URL_BASE . 'assets/admin.js', array(), EMPEDIA_CLOUD_VERSION, true );
		wp_localize_script(
			'empedia-cloud-admin',
			'EmpediaCloud',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'empedia_cloud_scan' ),
				'i18n'  => array(
					'starting' => __( 'Starting the scan …', 'empedia-shield' ),
					'running'  => __( 'The scan is running. This can take several minutes.', 'empedia-shield' ),
					'done'     => __( 'The scan is finished.', 'empedia-shield' ),
					'report'   => __( 'View the report in EMPEDIAcloud', 'empedia-shield' ),
					'failed'   => __( 'The scan could not be completed.', 'empedia-shield' ),
					'error'    => __( 'The request failed. Please try again.', 'empedia-shield' ),
				),
			)
		);
	}

	/** Return from the cloud (browser flow); runs before any output so the redirect works. */
	public static function early_return() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$ret = Empedia_Cloud_Connect::handle_return();
		if ( null !== $ret ) {
			self::flash( is_wp_error( $ret ) ? 'error' : 'success', is_wp_error( $ret ) ? $ret->get_error_message() : __( 'The site is connected. The first data will appear in a few minutes.', 'empedia-shield' ) );
			wp_safe_redirect( Empedia_Cloud_Connect::page_url() );
			exit;
		}
	}

	/* ------------------------------------------------------------------ notices */

	/**
	 * Date (and time) in the format of the signed-in person's language, not the site's
	 * English-style format settings. English (US) keeps the WordPress setting.
	 */
	public static function fmt_date( $ts, $with_time = true ) {
		$loc  = (string) determine_locale();
		$lang = strtolower( substr( $loc, 0, 2 ) );
		$map  = array(
			'de' => 'd.m.Y',
			'pl' => 'd.m.Y',
			'tr' => 'd.m.Y',
			'nl' => 'd-m-Y',
			'fr' => 'd/m/Y',
			'es' => 'd/m/Y',
			'it' => 'd/m/Y',
			'pt' => 'd/m/Y',
		);
		if ( 'en_GB' === $loc || 'en_AU' === $loc ) {
			$d = 'd/m/Y';
		} elseif ( isset( $map[ $lang ] ) ) {
			$d = $map[ $lang ];
		} else {
			return wp_date( get_option( 'date_format' ) . ( $with_time ? ' ' . get_option( 'time_format' ) : '' ), (int) $ts );
		}
		return wp_date( $with_time ? $d . ', H:i' : $d, (int) $ts );
	}

	public static function flash( $type, $text ) {
		set_transient( 'empedia_cloud_flash_' . get_current_user_id(), array( $type, $text ), 60 );
	}

	public static function notices() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		$f = get_transient( 'empedia_cloud_flash_' . get_current_user_id() );
		if ( $f ) {
			delete_transient( 'empedia_cloud_flash_' . get_current_user_id() );
			printf( '<div class="notice notice-%1$s is-dismissible"><p>%2$s</p></div>', esc_attr( $f[0] ), esc_html( $f[1] ) );
		}
		if ( get_option( 'empedia_cloud_token_invalid' ) && Empedia_Cloud_Client::is_connected() ) {
			printf(
				'<div class="notice notice-warning"><p>%1$s <a href="%2$s">%3$s</a></p></div>',
				esc_html__( 'EMPEDIAcloud: the connection was ended in your account.', 'empedia-shield' ),
				esc_url( Empedia_Cloud_Connect::page_url() ),
				esc_html__( 'Connect again', 'empedia-shield' )
			);
		}
	}

	/* ------------------------------------------------------------------ handlers */

	/** Capability check; every handler calls it first and then check_admin_referer() with its own nonce action. */
	private static function cap() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
	}

	private static function back() {
		wp_safe_redirect( Empedia_Cloud_Connect::page_url() );
		exit;
	}

	public static function handle_start() {
		self::cap();
		check_admin_referer( 'empedia_cloud_start' );
		if ( 0 !== strpos( home_url(), 'https://' ) && ! ( defined( 'EMPEDIA_CLOUD_ALLOW_HTTP' ) && EMPEDIA_CLOUD_ALLOW_HTTP ) ) {
			self::flash( 'error', Empedia_Cloud_Client::error_text( 'https_required' ) );
			self::back();
		}
		// The cloud is an external host: allow exactly this address for the redirect.
		$target = Empedia_Cloud_Connect::start_url();
		add_filter(
			'allowed_redirect_hosts',
			function ( $hosts ) use ( $target ) {
				$hosts[] = wp_parse_url( $target, PHP_URL_HOST );
				return $hosts;
			}
		);
		wp_safe_redirect( $target );
		exit;
	}

	public static function handle_code() {
		self::cap();
		check_admin_referer( 'empedia_cloud_code' );
		$code = isset( $_POST['empedia_code'] ) ? strtoupper( trim( sanitize_text_field( wp_unslash( $_POST['empedia_code'] ) ) ) ) : '';
		if ( ! preg_match( '/^ECW-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/', $code ) ) {
			self::flash( 'error', __( 'Please enter the connection code exactly as shown in EMPEDIAcloud (ECW-XXXX-XXXX-XXXX).', 'empedia-shield' ) );
			self::back();
		}
		$r = Empedia_Cloud_Connect::exchange( $code );
		self::flash( is_wp_error( $r ) ? 'error' : 'success', is_wp_error( $r ) ? $r->get_error_message() : __( 'The site is connected.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_apply() {
		self::cap();
		check_admin_referer( 'empedia_cloud_apply' );
		$action = isset( $_POST['rule_action'] ) ? sanitize_key( wp_unslash( $_POST['rule_action'] ) ) : '';
		$r      = Empedia_Cloud_Hardening::apply( $action );
		self::finish_hardening( $action, $r, __( 'The setting was applied.', 'empedia-shield' ) );
	}

	public static function handle_revert() {
		self::cap();
		check_admin_referer( 'empedia_cloud_revert' );
		$action = isset( $_POST['rule_action'] ) ? sanitize_key( wp_unslash( $_POST['rule_action'] ) ) : '';
		$r      = Empedia_Cloud_Hardening::revert( $action );
		self::finish_hardening( $action, $r, __( 'The setting was reverted.', 'empedia-shield' ) );
	}

	/** After applying or reverting: measure again what changed, report it and show the result. */
	private static function finish_hardening( $action, $result, $ok_text ) {
		if ( is_wp_error( $result ) ) {
			self::flash( 'error', $result->get_error_message() );
			self::back();
		}
		if ( Empedia_Cloud_Client::is_connected() ) {
			Empedia_Cloud_Plugin::send_inventory( Empedia_Cloud_Probes::for_action( $action ) );
		}
		self::flash( 'success', $ok_text );
		self::back();
	}

	/** Measures one setting again (no change to the site) and reports the result. */
	public static function handle_remeasure() {
		self::cap();
		check_admin_referer( 'empedia_cloud_remeasure' );
		$action = isset( $_POST['rule_action'] ) ? sanitize_key( wp_unslash( $_POST['rule_action'] ) ) : '';
		if ( ! in_array( $action, Empedia_Cloud_Hardening::actions(), true ) ) {
			self::flash( 'error', __( 'Unknown action.', 'empedia-shield' ) );
			self::back();
		}
		$r = Empedia_Cloud_Plugin::send_inventory( Empedia_Cloud_Probes::for_action( $action ) );
		self::flash( is_wp_error( $r ) ? 'error' : 'success', is_wp_error( $r ) ? $r->get_error_message() : __( 'The setting was measured again.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_refresh() {
		self::cap();
		check_admin_referer( 'empedia_cloud_refresh' );
		$r = Empedia_Cloud_Plugin::send_inventory( true );
		self::flash( is_wp_error( $r ) ? 'error' : 'success', is_wp_error( $r ) ? $r->get_error_message() : __( 'The data was sent to EMPEDIAcloud.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_verify() {
		self::cap();
		check_admin_referer( 'empedia_cloud_verify' );
		$r = Empedia_Cloud_Plugin::verify_now();
		if ( true === $r ) {
			self::flash( 'success', __( 'The domain is verified.', 'empedia-shield' ) );
		} elseif ( is_wp_error( $r ) ) {
			self::flash( 'error', $r->get_error_message() );
		} else {
			self::flash( 'warning', __( 'The verification file could not be read yet. Please check that the address below opens in a browser and try again.', 'empedia-shield' ) );
		}
		self::back();
	}

	public static function handle_disconnect() {
		self::cap();
		check_admin_referer( 'empedia_cloud_disconnect' );
		Empedia_Cloud_Connect::disconnect();
		self::flash( 'success', __( 'The connection was ended.', 'empedia-shield' ) );
		self::back();
	}

	public static function ajax_scan_start() {
		check_ajax_referer( 'empedia_cloud_scan', 'nonce' );
		if ( ! current_user_can( self::CAP ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'empedia-shield' ) ), 403 );
		}
		$r = Empedia_Cloud_Client::request( 'POST', '/scan', array( 'kind' => 'quick' ), true, 30 );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		wp_send_json_success( array( 'job' => isset( $r['job_id'] ) ? (string) $r['job_id'] : '' ) );
	}

	public static function ajax_scan_poll() {
		check_ajax_referer( 'empedia_cloud_scan', 'nonce' );
		if ( ! current_user_can( self::CAP ) ) {
			wp_send_json_error( array( 'message' => __( 'You are not allowed to do this.', 'empedia-shield' ) ), 403 );
		}
		$job = isset( $_POST['job'] ) ? preg_replace( '/[^0-9a-fA-F-]/', '', sanitize_text_field( wp_unslash( $_POST['job'] ) ) ) : '';
		if ( '' === $job ) {
			wp_send_json_error( array( 'message' => __( 'The request failed. Please try again.', 'empedia-shield' ) ) );
		}
		$r = Empedia_Cloud_Client::request( 'GET', '/scan/' . rawurlencode( $job ), null, true, 20 );
		if ( is_wp_error( $r ) ) {
			wp_send_json_error( array( 'message' => $r->get_error_message() ) );
		}
		$out = array(
			'status'  => isset( $r['status'] ) ? sanitize_key( (string) $r['status'] ) : 'unknown',
			'scan_id' => isset( $r['scan_id'] ) ? preg_replace( '/[^0-9a-fA-F-]/', '', (string) $r['scan_id'] ) : '',
		);
		if ( 'completed' === $out['status'] ) {
			delete_transient( Empedia_Cloud_Plugin::STATUS_TRANSIENT );
			$out['report'] = '' !== $out['scan_id'] ? Empedia_Cloud_Client::base() . '/scans-detail.html?id=' . rawurlencode( $out['scan_id'] ) : '';
		}
		wp_send_json_success( $out );
	}

	/* ------------------------------------------------------------------ upgrade notices */

	/** Closes one upgrade notice for the current user ( stored per user, no network ). */
	public static function handle_dismiss() {
		self::cap();
		check_admin_referer( 'empedia_cloud_dismiss' );
		$key = isset( $_GET['notice'] ) ? sanitize_key( wp_unslash( $_GET['notice'] ) ) : '';
		if ( in_array( $key, array( 'free', 'inactive' ), true ) ) {
			$m = get_user_meta( get_current_user_id(), self::DISMISS_META, true );
			$m = is_array( $m ) ? $m : array();
			$m[ $key ] = time();
			update_user_meta( get_current_user_id(), self::DISMISS_META, $m );
		}
		$back = wp_get_referer();
		wp_safe_redirect( $back ? $back : Empedia_Cloud_Connect::page_url() );
		exit;
	}

	/** A closed notice stays closed; the "paused" notice returns after a week because it needs action. */
	private static function dismissed( $key ) {
		$m = get_user_meta( get_current_user_id(), self::DISMISS_META, true );
		if ( ! is_array( $m ) || empty( $m[ $key ] ) ) {
			return false;
		}
		return 'inactive' === $key ? ( time() - (int) $m[ $key ] ) < WEEK_IN_SECONDS : true;
	}

	/** Address of the plans page: from the cloud, but only if it is on the cloud's own host. */
	private static function plans_url( $status ) {
		$base = Empedia_Cloud_Client::base();
		$url  = is_array( $status ) && ! empty( $status['plans_url'] ) ? esc_url_raw( (string) $status['plans_url'] ) : '';
		if ( '' === $url || wp_parse_url( $url, PHP_URL_HOST ) !== wp_parse_url( $base, PHP_URL_HOST ) ) {
			$url = $base . '/pricing.html#tab-wordpress';
		}
		return $url;
	}

	/**
	 * Upgrade hint, only where a Pro service is missing for this site ( tier free ) or the site is paused ( tier inactive ).
	 * Uses the status that is already stored - it never causes a request. Closable per user.
	 *
	 * @param array $status Status as delivered by the cloud ( or the stored last one ).
	 * @param bool  $short  Short form for the dashboard widget.
	 */
	public static function upsell( $status, $short = false ) {
		if ( ! current_user_can( self::CAP ) || ! is_array( $status ) || empty( $status['installation']['level'] ) ) {
			return;
		}
		$level = (string) $status['installation']['level'];
		if ( ! in_array( $level, array( 'free', 'inactive' ), true ) || self::dismissed( $level ) ) {
			return;
		}
		if ( 'inactive' === $level ) {
			$text = $short
				? __( 'This site is paused in EMPEDIAcloud because all places of your plan are in use.', 'empedia-shield' )
				: __( 'This site is paused in EMPEDIAcloud because all places of your plan are in use. The cloud does not evaluate its data right now; the protection in this plugin keeps working. Free a place by disconnecting another site, or add more sites to your plan.', 'empedia-shield' );
			$kind = 'warning';
		} else {
			$text = $short
				? __( 'Cloud free tier: alerts, sign-in with your EMPEDIAcloud account and backup targets with sign-in (Google Drive and others) are part of Pro. The plugin itself is fully usable.', 'empedia-shield' )
				: __( 'Everything in this plugin works without a plan: security settings, sign-in protection, file check, firewall, backups and bot protection. The optional EMPEDIAcloud connection of this site is on the free tier; availability alerts, alerts for files, changes and backups, sign-in with your EMPEDIAcloud account and backup targets with sign-in (Google Drive, OneDrive, Dropbox, Box, pCloud) come with Pro.', 'empedia-shield' );
			$kind = 'info';
		}
		$close = wp_nonce_url( add_query_arg( array( 'action' => 'empedia_cloud_dismiss', 'notice' => $level ), admin_url( 'admin-post.php' ) ), 'empedia_cloud_dismiss' );
		printf(
			'<div class="notice notice-%1$s inline empedia-upsell"><p>%2$s <a class="button button-small" href="%3$s" target="_blank" rel="noopener noreferrer">%4$s</a> <a href="%5$s">%6$s</a></p></div>',
			esc_attr( $kind ),
			esc_html( $text ),
			esc_url( self::plans_url( $status ) ),
			esc_html__( 'View plans', 'empedia-shield' ),
			esc_url( $close ),
			esc_html__( 'Hide this notice', 'empedia-shield' )
		);
	}

	/* ------------------------------------------------------------------ rendering */

	private static function form_button( $action, $label, $extra = array(), $class = 'button' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-inline">';
		echo '<input type="hidden" name="action" value="empedia_cloud_' . esc_attr( $action ) . '">';
		wp_nonce_field( 'empedia_cloud_' . $action );
		foreach ( $extra as $k => $v ) {
			echo '<input type="hidden" name="' . esc_attr( $k ) . '" value="' . esc_attr( $v ) . '">';
		}
		echo '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	private static function badge( $text, $kind = '' ) {
		return '<span class="empedia-badge ' . esc_attr( $kind ) . '">' . esc_html( $text ) . '</span>';
	}

	private static function sev_badge( $sev ) {
		$labels = array(
			'high'   => __( 'High', 'empedia-shield' ),
			'medium' => __( 'Medium', 'empedia-shield' ),
			'low'    => __( 'Low', 'empedia-shield' ),
		);
		$kind = 'high' === $sev ? 'bad' : ( 'medium' === $sev ? 'warn' : '' );
		return self::badge( isset( $labels[ $sev ] ) ? $labels[ $sev ] : $sev, $kind );
	}

	public static function render() {
		if ( ! current_user_can( self::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap empedia-cloud"><h1>' . esc_html__( 'EMPEDIA Shield', 'empedia-shield' ) . '</h1>';
		$tab  = self::current_tab();
		$tabs = array(
			'overview' => __( 'Overview', 'empedia-shield' ),
			'login'    => __( 'Sign-in protection', 'empedia-shield' ),
			'files'    => __( 'Files', 'empedia-shield' ),
			'firewall' => __( 'Firewall', 'empedia-shield' ),
			'bots'     => __( 'Bot protection', 'empedia-shield' ),
			'comments' => __( 'Comments', 'empedia-shield' ),
			'backups'  => __( 'Backups', 'empedia-shield' ),
		);
		echo '<nav class="nav-tab-wrapper" style="margin-bottom:16px">';
		foreach ( $tabs as $k => $label ) {
			printf( '<a href="%s" class="nav-tab%s">%s</a>', esc_url( self::tab_url( $k ) ), $k === $tab ? ' nav-tab-active' : '', esc_html( $label ) );
		}
		echo '</nav>';
		if ( 'login' === $tab ) {
			Empedia_Cloud_Protect_Admin::render_tab();
		} elseif ( 'firewall' === $tab ) {
			Empedia_Cloud_Firewall_Admin::render_tab();
		} elseif ( 'files' === $tab ) {
			Empedia_Cloud_Files_Admin::render_tab();
		} elseif ( 'bots' === $tab ) {
			Empedia_Cloud_Bots::render_tab();
		} elseif ( 'comments' === $tab ) {
			Empedia_Cloud_Comments::render_tab();
		} elseif ( 'backups' === $tab ) {
			Empedia_Cloud_Backup_Admin::render_tab();
		} elseif ( ! Empedia_Cloud_Client::is_connected() ) {
			self::render_disconnected();
		} else {
			self::render_connected();
		}
		echo '</div>';
	}

	public static function current_tab() {
		$t = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'overview'; // phpcs:ignore WordPress.Security.NonceVerification
		return in_array( $t, array( 'overview', 'login', 'files', 'firewall', 'bots', 'comments', 'backups' ), true ) ? $t : 'overview';
	}

	public static function tab_url( $tab ) {
		return 'overview' === $tab ? Empedia_Cloud_Connect::page_url() : add_query_arg( 'tab', $tab, Empedia_Cloud_Connect::page_url() );
	}

	private static function render_disconnected() {
		$https = 0 === strpos( home_url(), 'https://' );
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Connect this site', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Connect this site with your EMPEDIAcloud account to see how well it is protected, which known vulnerabilities affect WordPress, plugins and themes, and to be alerted when it is not reachable.', 'empedia-shield' ) . '</p>';
		if ( ! $https ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html( Empedia_Cloud_Client::error_text( 'https_required' ) ) . '</p></div>';
		}
		echo '<p>';
		self::form_button( 'start', __( 'Connect with EMPEDIAcloud', 'empedia-shield' ), array(), 'button button-primary button-hero' );
		echo '</p>';
		printf(
			'<p class="description">%s <a href="%s" target="_blank" rel="noopener noreferrer">%s</a></p>',
			esc_html__( 'You need an EMPEDIAcloud account.', 'empedia-shield' ),
			esc_url( Empedia_Cloud_Client::base() . '/register.html' ),
			esc_html__( 'Create an account', 'empedia-shield' )
		);
		echo '</div>';

		echo '<div class="empedia-card"><h2>' . esc_html__( 'With a connection code', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Agencies can create a connection code in EMPEDIAcloud (WordPress → Connect a site) and enter it here, so no sign-in is needed on the client’s site.', 'empedia-shield' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-code"><input type="hidden" name="action" value="empedia_cloud_code">';
		wp_nonce_field( 'empedia_cloud_code' );
		echo '<input type="text" name="empedia_code" class="regular-text code" placeholder="ECW-XXXX-XXXX-XXXX" autocomplete="off" maxlength="19" required> ';
		echo '<button type="submit" class="button">' . esc_html__( 'Connect', 'empedia-shield' ) . '</button></form></div>';

		self::render_local_hardening();

		echo '<div class="empedia-card"><h2>' . esc_html__( 'What is sent', 'empedia-shield' ) . '</h2><ul class="empedia-list">';
		foreach ( array(
			__( 'Versions of WordPress, PHP and the database, and the list of plugins and themes with their versions.', 'empedia-shield' ),
			__( 'Security-relevant settings as yes/no values and the number of administrators.', 'empedia-shield' ),
			__( 'The address of this site. The plugin also requests a few addresses of this site itself (for example the uploads folder) to measure how it responds.', 'empedia-shield' ),
			__( 'Not sent: content, posts, visitor data, user names, e-mail addresses or passwords.', 'empedia-shield' ),
		) as $line ) {
			echo '<li>' . esc_html( $line ) . '</li>';
		}
		echo '</ul></div>';
	}

	/** Titles and short texts of the hardening actions, for the list that works without a connection. */
	private static function local_hardening_texts() {
		return array(
			'uploads_php'      => array( __( 'No PHP in the uploads folder', 'empedia-shield' ), __( 'Blocks the execution of PHP files in wp-content/uploads (.htaccess).', 'empedia-shield' ) ),
			'file_edit'        => array( __( 'Switch off the file editor', 'empedia-shield' ), __( 'Removes the theme and plugin editor from the dashboard.', 'empedia-shield' ) ),
			'debug_log'        => array( __( 'Protect the debug log', 'empedia-shield' ), __( 'Blocks public access to wp-content/debug.log (.htaccess).', 'empedia-shield' ) ),
			'rest_users'       => array( __( 'Hide the user list in the REST API', 'empedia-shield' ), __( 'Visitors who are not signed in can no longer list user names.', 'empedia-shield' ) ),
			'auto_update_core' => array( __( 'Automatic minor WordPress updates', 'empedia-shield' ), __( 'Security releases of WordPress are installed automatically.', 'empedia-shield' ) ),
			'security_headers' => array( __( 'Security headers', 'empedia-shield' ), __( 'Sends X-Content-Type-Options, X-Frame-Options and a referrer policy.', 'empedia-shield' ) ),
			'xmlrpc'           => array( __( 'Switch off XML-RPC', 'empedia-shield' ), __( 'Closes xmlrpc.php, a common target for password guessing.', 'empedia-shield' ) ),
			'author_enum'      => array( __( 'Block user name guessing', 'empedia-shield' ), __( 'Stops ?author=1 requests and the users sitemap from revealing user names.', 'empedia-shield' ) ),
			'generator'        => array( __( 'Hide the WordPress version', 'empedia-shield' ), __( 'Removes the generator tag from pages and feeds.', 'empedia-shield' ) ),
			'login_errors'     => array( __( 'Neutral sign-in errors', 'empedia-shield' ), __( 'The sign-in form no longer says whether the user name or the password was wrong.', 'empedia-shield' ) ),
		);
	}

	/** The one-click fixes work without a connection to EMPEDIAcloud: this list is shown while the site is not connected. */
	private static function render_local_hardening() {
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Security settings (work without a connection)', 'empedia-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( 'These settings can be applied and reverted at any time. Nothing touches wp-config.php; file based settings only write a clearly marked block into an .htaccess file. When the site is connected to EMPEDIAcloud, it also runs a security check of your site and shows which of them are needed.', 'empedia-shield' ) . '</p>';
		echo '<table class="widefat striped empedia-rules"><tbody>';
		foreach ( self::local_hardening_texts() as $action => $t ) {
			$on = Empedia_Cloud_Hardening::is_applied( $action );
			echo '<tr><td>' . self::badge( $on ? __( 'Applied', 'empedia-shield' ) : __( 'Not applied', 'empedia-shield' ), $on ? 'good' : '' ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td><strong>' . esc_html( $t[0] ) . '</strong><div class="description">' . esc_html( $t[1] ) . '</div></td><td class="empedia-right">';
			if ( $on ) {
				self::form_button( 'revert', __( 'Revert', 'empedia-shield' ), array( 'rule_action' => $action ) );
			} else {
				self::form_button( 'apply', __( 'Secure now', 'empedia-shield' ), array( 'rule_action' => $action ), 'button button-primary' );
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	private static function render_connected() {
		$conn   = Empedia_Cloud_Client::conn();
		$status = Empedia_Cloud_Plugin::get_status( false );
		$stale  = null;
		if ( is_wp_error( $status ) ) {
			$last = Empedia_Cloud_Plugin::last_status();
			if ( $last ) {
				$stale  = $last['at'];
				$status = $last['status'];
			}
		}

		echo '<div class="empedia-card empedia-head"><div>';
		echo '<strong class="empedia-domain">' . esc_html( isset( $conn['domain'] ) ? $conn['domain'] : '' ) . '</strong> ';
		$level = is_array( $status ) && isset( $status['installation']['level'] ) ? $status['installation']['level'] : '';
		if ( $level ) {
			$names = array(
				'pro'      => __( 'Pro', 'empedia-shield' ),
				'free'     => __( 'Free', 'empedia-shield' ),
				'inactive' => __( 'Idle', 'empedia-shield' ),
			);
			echo wp_kses_post( self::badge( isset( $names[ $level ] ) ? $names[ $level ] : $level, 'pro' === $level ? 'good' : ( 'inactive' === $level ? 'warn' : '' ) ) );
		}
		$sync = (int) get_option( 'empedia_cloud_last_sync', 0 );
		echo '<div class="description">' . esc_html(
			$sync
				/* translators: %s: time ago, e.g. "5 minutes" */
				? sprintf( __( 'Last data sent %s ago.', 'empedia-shield' ), human_time_diff( $sync, time() ) )
				: __( 'No data sent yet.', 'empedia-shield' )
		) . '</div></div><div class="empedia-actions">';
		self::form_button( 'refresh', __( 'Send data now', 'empedia-shield' ) );
		echo '<button type="button" class="button" id="empedia-scan">' . esc_html__( 'Start security scan', 'empedia-shield' ) . '</button>';
		self::form_button( 'disconnect', __( 'Disconnect', 'empedia-shield' ), array(), 'button button-link-delete' );
		echo '</div></div>';
		echo '<div id="empedia-scan-msg" class="notice inline" style="display:none"><p></p></div>';
		self::upsell( $status );

		if ( is_wp_error( $status ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $status->get_error_message() ) . '</p></div>';
			return;
		}
		if ( $stale ) {
			/* translators: %s: time ago */
			echo '<div class="notice notice-warning inline"><p>' . esc_html( sprintf( __( 'EMPEDIAcloud is not reachable right now. Showing the state from %s ago.', 'empedia-shield' ), human_time_diff( $stale, time() ) ) ) . '</p></div>';
		}
		$verified = ! empty( $status['installation']['verified'] );
		if ( $verified && empty( $conn['verified'] ) ) {
			$conn['verified'] = true;
			Empedia_Cloud_Client::save_conn( $conn );
			delete_option( 'empedia_cloud_verify' );
		}
		if ( ! $verified ) {
			self::render_verify_box();
		}
		if ( 'inactive' === $level ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'This site is idle because all site slots of your plan are in use. It stays connected, but is not evaluated until a slot is free.', 'empedia-shield' ) . '</p></div>';
		}
		if ( ! empty( $status['hint'] ) && 'no_inventory' === $status['hint'] ) {
			echo '<div class="notice notice-info inline"><p>' . esc_html__( 'The first data is on its way. Reload this page in a few minutes or click “Send data now”.', 'empedia-shield' ) . '</p></div>';
		}
		$inside = isset( $status['inside'] ) ? $status['inside'] : null;
		if ( $inside ) {
			self::render_summary( $status, $inside );
			self::render_hardening( $inside['hardening'] );
			self::render_vulns( $inside['vulns'] );
		}
		$detail = Empedia_Cloud_Client::base() . '/wordpress-detail.html?id=' . rawurlencode( isset( $conn['installation_id'] ) ? $conn['installation_id'] : '' );
		printf( '<p><a href="%s" target="_blank" rel="noopener noreferrer">%s</a></p>', esc_url( $detail ), esc_html__( 'Open this site in EMPEDIAcloud', 'empedia-shield' ) );
	}

	private static function render_verify_box() {
		$v = get_option( 'empedia_cloud_verify' );
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Verify the domain', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'EMPEDIAcloud has to be sure that this domain belongs to you before scans and monitoring can run. The plugin delivers a small proof file by itself.', 'empedia-shield' ) . '</p>';
		if ( is_array( $v ) && ! empty( $v['path'] ) ) {
			$origin = wp_parse_url( home_url(), PHP_URL_SCHEME ) . '://' . wp_parse_url( home_url(), PHP_URL_HOST );
			printf( '<p><code>%s</code></p>', esc_html( $origin . $v['path'] ) );
		}
		echo '<p>';
		self::form_button( 'verify', __( 'Check again', 'empedia-shield' ), array(), 'button button-primary' );
		echo '</p></div>';
	}

	private static function render_summary( $status, $inside ) {
		$h  = $inside['hardening'];
		$v  = $inside['vulns'];
		$u  = $inside['updates'];
		$up = (int) $u['plugins'] + (int) $u['themes'] + ( ! empty( $u['core'] ) ? 1 : 0 );
		echo '<div class="empedia-tiles">';
		self::tile(
			_x( 'Protection', 'security score of the site', 'empedia-shield' ),
			null === $h['score'] ? '—' : $h['score'] . ' ' . ( isset( $h['grade'] ) ? $h['grade'] : '' ),
			/* translators: %d: number of open points */
			sprintf( _n( '%d point open', '%d points open', (int) $h['counts']['fail'], 'empedia-shield' ), (int) $h['counts']['fail'] ),
			null === $h['score'] ? '' : ( $h['score'] >= 90 ? 'good' : ( $h['score'] >= 70 ? 'warn' : 'bad' ) )
		);
		self::tile(
			__( 'Known vulnerabilities', 'empedia-shield' ),
			! empty( $v['available'] ) ? (string) ( $v['counts']['high'] + $v['counts']['medium'] + $v['counts']['low'] ) : '—',
			! empty( $v['available'] )
				/* translators: 1: high, 2: medium, 3: low */
				? sprintf( __( '%1$d high · %2$d medium · %3$d low', 'empedia-shield' ), $v['counts']['high'], $v['counts']['medium'], $v['counts']['low'] )
				: __( 'Data source not reachable', 'empedia-shield' ),
			$v['counts']['high'] ? 'bad' : ( $v['counts']['medium'] ? 'warn' : ( ! empty( $v['available'] ) ? 'good' : '' ) )
		);
		self::tile(
			__( 'Updates available', 'empedia-shield' ),
			(string) $up,
			/* translators: 1: plugins, 2: themes */
			sprintf( __( 'Plugins %1$d · Themes %2$d', 'empedia-shield' ), (int) $u['plugins'], (int) $u['themes'] ) . ( ! empty( $u['core'] ) ? ' · ' . __( 'WordPress', 'empedia-shield' ) : '' ),
			$up ? 'warn' : 'good'
		);
		if ( ! empty( $status['outside'] ) ) {
			$o = $status['outside'];
			self::tile( __( 'Outside scan', 'empedia-shield' ), esc_html( (string) $o['grade'] ) . ' ' . (int) $o['score'], '', ( (int) $o['score'] >= 90 ? 'good' : ( (int) $o['score'] >= 70 ? 'warn' : 'bad' ) ) );
		}
		if ( 'pro' === ( isset( $status['installation']['level'] ) ? $status['installation']['level'] : '' ) ) {
			$st = isset( $status['uptime']['state'] ) ? $status['uptime']['state'] : 'unknown';
			$tx = array(
				'up'      => __( 'Online', 'empedia-shield' ),
				'down'    => __( 'Unreachable', 'empedia-shield' ),
				'unknown' => __( 'Not known yet', 'empedia-shield' ),
			);
			self::tile( __( 'Availability', 'empedia-shield' ), isset( $tx[ $st ] ) ? $tx[ $st ] : $st, '', 'up' === $st ? 'good' : ( 'down' === $st ? 'bad' : '' ) );
		}
		echo '</div>';
	}

	private static function tile( $label, $value, $sub = '', $kind = '' ) {
		echo '<div class="empedia-tile ' . esc_attr( $kind ) . '"><div class="empedia-tile-label">' . esc_html( $label ) . '</div><div class="empedia-tile-value">' . esc_html( $value ) . '</div>';
		if ( '' !== $sub ) {
			echo '<div class="empedia-tile-sub">' . esc_html( $sub ) . '</div>';
		}
		echo '</div>';
	}

	private static function render_hardening( $h ) {
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Security settings', 'empedia-shield' ) . '</h2>';
		echo '<p class="description">' . esc_html__( '“Secure now” changes the setting with the plugin and can be reverted at any time. Everything else you do yourself – the instructions are shown with each point.', 'empedia-shield' ) . '</p>';
		echo '<table class="widefat striped empedia-rules"><thead><tr><th>' . esc_html__( 'Status', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Check', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Severity', 'empedia-shield' ) . '</th><th></th></tr></thead><tbody>';
		foreach ( $h['rules'] as $r ) {
			$state = isset( $r['state'] ) ? $r['state'] : 'unknown';
			$names = array(
				'ok'      => array( __( 'OK', 'empedia-shield' ), 'good' ),
				'fail'    => array( __( 'Action needed', 'empedia-shield' ), 'bad' ),
				'unknown' => array( __( 'Unknown', 'empedia-shield' ), '' ),
			);
			echo '<tr><td>' . self::badge( $names[ $state ][0], $names[ $state ][1] ) . '</td>'; // phpcs:ignore WordPress.Security.EscapeOutput
			echo '<td><strong>' . esc_html( $r['title'] ) . '</strong><div class="description">' . esc_html( $r['text'] ) . '</div>';
			$stuck = ! empty( $r['applied'] ) && 'fail' === $state && ! empty( $r['action'] );
			if ( $stuck ) {
				echo '<div class="empedia-note">' . esc_html( self::stuck_hint( $r['action'] ) ) . self::probe_details( $r['action'] ) . '</div>'; // phpcs:ignore WordPress.Security.EscapeOutput
			}
			echo '</td><td>' . self::sev_badge( $r['severity'] ) . '</td><td class="empedia-right">'; // phpcs:ignore WordPress.Security.EscapeOutput
			if ( 'plugin' === $r['fix'] && ! empty( $r['action'] ) ) {
				if ( ! empty( $r['applied'] ) ) {
					if ( $stuck ) {
						self::form_button( 'remeasure', __( 'Measure again', 'empedia-shield' ), array( 'rule_action' => $r['action'] ), 'button button-primary' );
					}
					self::form_button( 'revert', __( 'Revert', 'empedia-shield' ), array( 'rule_action' => $r['action'] ) );
				} elseif ( 'fail' === $state ) {
					self::form_button( 'apply', __( 'Secure now', 'empedia-shield' ), array( 'rule_action' => $r['action'] ), 'button button-primary' );
				}
			}
			echo '</td></tr>';
		}
		echo '</tbody></table></div>';
	}

	/** What the last measurement of an action actually saw (already escaped HTML). */
	private static function probe_details( $action ) {
		$names = Empedia_Cloud_Probes::for_action( $action );
		$info  = Empedia_Cloud_Probes::info();
		if ( ! $names || empty( $info[ $names[0] ] ) ) {
			return '';
		}
		$i = $info[ $names[0] ];
		$c = array();
		foreach ( (array) ( isset( $i['cache'] ) ? $i['cache'] : array() ) as $k => $v ) {
			$c[] = $k . ': ' . $v;
		}
		/* translators: 1: HTTP status code, 2: host name, 3: response headers that concern caching */
		$t = sprintf( __( 'Last measurement: HTTP %1$s from %2$s%3$s.', 'empedia-shield' ), (int) $i['code'], (string) $i['host'], $c ? ' (' . implode( ', ', $c ) . ')' : '' );
		return '<br><small>' . esc_html( $t ) . '</small>';
	}

	/** Why a setting that is switched on can still be measured as open (shown next to the "Measure again" button). */
	private static function stuck_hint( $action ) {
		$cache = __( 'The setting is active, but the site still answers visitors as before. This is usually a page cache, a CDN or a server cache that serves an older copy, or another plugin that overrides the setting. Clear the caches and measure again.', 'empedia-shield' );
		switch ( $action ) {
			case 'uploads_php':
			case 'debug_log':
				return __( 'The rule was written, but the site still answers as before. Your web server may ignore .htaccess files (for example nginx): please add the rule to the server configuration or ask your host. A cache can also serve an older copy – clear it and measure again.', 'empedia-shield' );
			case 'rest_users':
			case 'author_enum':
			case 'security_headers':
				return $cache;
			default:
				return __( 'The setting is active, but the last measurement still showed the old state. Measure again; if it stays open, a cache or another plugin is probably overriding it.', 'empedia-shield' );
		}
	}

	private static function render_vulns( $v ) {
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Known vulnerabilities', 'empedia-shield' ) . '</h2>';
		if ( empty( $v['available'] ) ) {
			echo '<p>' . esc_html__( 'The vulnerability database could not be reached. This is checked again automatically.', 'empedia-shield' ) . '</p></div>';
			return;
		}
		if ( empty( $v['items'] ) ) {
			echo '<p>' . esc_html__( 'No vulnerabilities are known for the detected versions.', 'empedia-shield' ) . '</p>';
		} else {
			echo '<table class="widefat striped"><tbody>';
			foreach ( $v['items'] as $i ) {
				echo '<tr><td>' . self::sev_badge( $i['severity'] ) . '</td><td><strong>' . esc_html( $i['title'] ) . '</strong>'; // phpcs:ignore WordPress.Security.EscapeOutput
				if ( ! empty( $i['recommendation'] ) ) {
					echo '<div class="description">' . esc_html( $i['recommendation'] ) . '</div>';
				}
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '<p class="description">' . esc_html__( 'Data: WPVulnerability (CC0). Findings are hints, not a guarantee.', 'empedia-shield' ) . ' <a href="https://www.wpvulnerability.com" target="_blank" rel="noopener noreferrer">wpvulnerability.com</a></p></div>';
	}

	/* ------------------------------------------------------------------ dashboard widget */

	public static function dashboard_widget() {
		if ( ! current_user_can( self::CAP ) ) {
			return;
		}
		wp_add_dashboard_widget( 'empedia_cloud_widget', __( 'EMPEDIA Shield', 'empedia-shield' ), array( __CLASS__, 'widget' ) );
	}

	/** Uses only stored data – the dashboard must never wait for the network. */
	public static function widget() {
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			echo '<p>' . esc_html__( 'This site is not connected to EMPEDIAcloud yet.', 'empedia-shield' ) . '</p>';
			printf( '<p><a class="button button-primary" href="%s">%s</a></p>', esc_url( Empedia_Cloud_Connect::page_url() ), esc_html__( 'Connect', 'empedia-shield' ) );
			return;
		}
		$last = Empedia_Cloud_Plugin::last_status();
		if ( $last ) {
			self::upsell( $last['status'], true );
		}
		$in = $last && isset( $last['status']['inside'] ) ? $last['status']['inside'] : null;
		if ( ! $in ) {
			printf( '<p>%s</p><p><a href="%s">%s</a></p>', esc_html__( 'No data yet.', 'empedia-shield' ), esc_url( Empedia_Cloud_Connect::page_url() ), esc_html__( 'Open EMPEDIAcloud', 'empedia-shield' ) );
			return;
		}
		$h = $in['hardening'];
		$v = $in['vulns'];
		echo '<ul class="empedia-widget-list">';
		/* translators: 1: score, 2: grade */
		echo '<li>' . esc_html( sprintf( __( 'Protection: %1$s %2$s', 'empedia-shield' ), null === $h['score'] ? '—' : $h['score'], isset( $h['grade'] ) ? $h['grade'] : '' ) ) . '</li>';
		/* translators: %d: number */
		echo '<li>' . esc_html( sprintf( __( 'High vulnerabilities: %d', 'empedia-shield' ), (int) $v['counts']['high'] ) ) . '</li>';
		/* translators: %d: number */
		echo '<li>' . esc_html( sprintf( __( 'Open points in the security check: %d', 'empedia-shield' ), (int) $h['counts']['fail'] ) ) . '</li>';
		// Backup state as judged by the cloud ( only problems are shown ).
		$bk_state = isset( $last['status']['backup_state'] ) ? $last['status']['backup_state'] : '';
		$bk_text  = array(
			'failed'  => __( 'Backup: the last backup failed', 'empedia-shield' ),
			'partial' => __( 'Backup: upload to a storage target failed', 'empedia-shield' ),
			'stale'   => __( 'Backup: overdue', 'empedia-shield' ),
			'none'    => __( 'Backup: none yet', 'empedia-shield' ),
		);
		if ( isset( $bk_text[ $bk_state ] ) ) {
			echo '<li><a href="' . esc_url( Empedia_Cloud_Connect::page_url( array( 'tab' => 'backups' ) ) ) . '"><strong>' . esc_html( $bk_text[ $bk_state ] ) . '</strong></a></li>';
		}
		if ( class_exists( 'Empedia_Captcha_Plugin' ) ) {
			$cp = Empedia_Captcha_Plugin::summary();
			if ( $cp['off'] ) {
				$txt = __( 'Bot protection: switched off (wp-config.php)', 'empedia-shield' );
			} elseif ( ! $cp['configured'] ) {
				$txt = __( 'Bot protection: not set up yet', 'empedia-shield' );
			} else {
				/* translators: 1: number of protected forms, 2: number of recently refused checks */
				$txt = sprintf( __( 'Bot protection: active on %1$d forms, %2$d refused checks recorded', 'empedia-shield' ), count( $cp['forms'] ), (int) $cp['refused'] );
			}
			echo '<li><a href="' . esc_url( Empedia_Cloud_Connect::page_url( array( 'tab' => 'bots' ) ) ) . '">' . esc_html( $txt ) . '</a></li>';
		}
		echo '</ul>';
		printf( '<p><a href="%s">%s</a></p>', esc_url( Empedia_Cloud_Connect::page_url() ), esc_html__( 'Open EMPEDIAcloud', 'empedia-shield' ) );
	}
}
