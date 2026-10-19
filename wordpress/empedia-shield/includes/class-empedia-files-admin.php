<?php
/**
 * Tab “Files”: file integrity scan ( start, progress, result, expected items ).
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Files_Admin {

	public static function init() {
		add_action( 'admin_post_empedia_cloud_files_ignore', array( __CLASS__, 'handle_ignore' ) );
		add_action( 'admin_post_empedia_cloud_files_unignore', array( __CLASS__, 'handle_unignore' ) );
		add_action( 'admin_post_empedia_cloud_files_settings', array( __CLASS__, 'handle_settings' ) );
		add_action( 'wp_ajax_empedia_cloud_files_start', array( __CLASS__, 'ajax_start' ) );
		add_action( 'wp_ajax_empedia_cloud_files_poll', array( __CLASS__, 'ajax_poll' ) );
	}

	/** Capability check; every handler calls it first and then check_admin_referer() with its own nonce action. */
	private static function cap() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
	}

	private static function back() {
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'files' ) );
		exit;
	}

	public static function handle_ignore() {
		self::cap();
		check_admin_referer( 'empedia_cloud_files_ignore' );
		Empedia_Cloud_Scanner::ignore( isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '' );
		Empedia_Cloud_Plugin::schedule_soon();
		self::back();
	}

	public static function handle_unignore() {
		self::cap();
		check_admin_referer( 'empedia_cloud_files_unignore' );
		Empedia_Cloud_Scanner::unignore( isset( $_POST['key'] ) ? sanitize_text_field( wp_unslash( $_POST['key'] ) ) : '' );
		Empedia_Cloud_Plugin::schedule_soon();
		self::back();
	}

	public static function handle_settings() {
		self::cap();
		check_admin_referer( 'empedia_cloud_files_settings' );
		update_option( Empedia_Cloud_Scanner::SETTINGS, array( 'auto' => ! empty( $_POST['auto'] ) ), false );
		Empedia_Cloud_Scanner::ensure_schedule();
		Empedia_Cloud_Admin::flash( 'success', __( 'Settings saved.', 'empedia-shield' ) );
		self::back();
	}

	public static function ajax_start() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) || ! check_ajax_referer( 'empedia_cloud_files', 'nonce', false ) ) {
			wp_send_json_error( array(), 403 );
		}
		Empedia_Cloud_Scanner::start( true );
		wp_send_json_success( self::progress() );
	}

	public static function ajax_poll() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) || ! check_ajax_referer( 'empedia_cloud_files', 'nonce', false ) ) {
			wp_send_json_error( array(), 403 );
		}
		// WP-Cron is triggered by visits; keep the scan going while this page is open.
		if ( Empedia_Cloud_Scanner::running() && ! get_transient( Empedia_Cloud_Scanner::LOCK ) ) {
			Empedia_Cloud_Scanner::tick();
		}
		wp_send_json_success( self::progress() );
	}

	private static function progress() {
		$s = Empedia_Cloud_Scanner::state();
		$labels = array(
			'core'       => __( 'Checking WordPress files …', 'empedia-shield' ),
			'core_extra' => __( 'Looking for foreign files in WordPress folders …', 'empedia-shield' ),
			'plugins'    => __( 'Checking plugins …', 'empedia-shield' ),
			'uploads'    => __( 'Looking at the uploads folder …', 'empedia-shield' ),
			'sig'        => __( 'Searching code for known patterns …', 'empedia-shield' ),
		);
		$running = Empedia_Cloud_Scanner::running();
		return array(
			'running' => $running,
			'label'   => $running && $s && isset( $labels[ $s['phase'] ] ) ? $labels[ $s['phase'] ] : '',
		);
	}

	public static function assets() {
		wp_enqueue_script( 'empedia-cloud-files', EMPEDIA_CLOUD_URL_BASE . 'assets/files.js', array(), EMPEDIA_CLOUD_VERSION, true );
		wp_localize_script(
			'empedia-cloud-files',
			'EmpediaFiles',
			array(
				'ajax'    => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'empedia_cloud_files' ),
				'running' => Empedia_Cloud_Scanner::running(),
				'i18n'    => array(
					'starting' => __( 'Starting the check …', 'empedia-shield' ),
					'error'    => __( 'The request failed. Please try again.', 'empedia-shield' ),
				),
			)
		);
	}

	private static function item_form( $action, $key, $label, $class = 'button-link' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="key" value="' . esc_attr( $key ) . '">';
		wp_nonce_field( $action );
		echo '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	public static function render_tab() {
		self::assets();
		$result  = Empedia_Cloud_Scanner::result();
		$running = Empedia_Cloud_Scanner::running();
		$kinds   = array(
			'core_modified'   => __( 'WordPress files that differ from the original', 'empedia-shield' ),
			'core_missing'    => __( 'WordPress files that are missing', 'empedia-shield' ),
			'core_extra'      => __( 'Foreign PHP files in the WordPress core folders', 'empedia-shield' ),
			'root_extra'      => __( 'Unknown PHP files in the main folder', 'empedia-shield' ),
			'plugin_modified' => __( 'Plugin files that differ from the original', 'empedia-shield' ),
			'plugin_extra'    => __( 'Additional PHP files inside plugins', 'empedia-shield' ),
			'uploads_php'     => __( 'PHP files in the uploads folder', 'empedia-shield' ),
			'sig'             => __( 'Code with suspicious patterns', 'empedia-shield' ),
		);
		$rules = array(
			'eval_base64'      => __( 'Code is decoded and executed', 'empedia-shield' ),
			'eval_decode'      => __( 'eval() with a decoding function', 'empedia-shield' ),
			'eval_input'       => __( 'eval() runs visitor input', 'empedia-shield' ),
			'assert_input'     => __( 'assert() with visitor input', 'empedia-shield' ),
			'shell_input'      => __( 'System command with visitor input or decoded content', 'empedia-shield' ),
			'webshell_name'    => __( 'Name of a well-known web shell', 'empedia-shield' ),
			'include_input'    => __( 'File inclusion from visitor input', 'empedia-shield' ),
			'input_function'   => __( 'Visitor input is called as a function', 'empedia-shield' ),
			'variable_call'    => __( 'Function called from a variable with visitor input', 'empedia-shield' ),
			'callback_exec'    => __( 'Callback trick that executes code', 'empedia-shield' ),
			'globals_call'     => __( 'Function call through $GLOBALS', 'empedia-shield' ),
			'phpinput_eval'    => __( 'php://input together with eval()', 'empedia-shield' ),
			'upload_php'       => __( 'Uploaded files are saved as PHP', 'empedia-shield' ),
			'rogue_admin'      => __( 'Creates an administrator by code', 'empedia-shield' ),
			'preg_e_input'     => __( 'preg_replace with /e and visitor input', 'empedia-shield' ),
			'htaccess_prepend' => __( '.htaccess includes a file in every PHP page', 'empedia-shield' ),
			'htaccess_handler' => __( '.htaccess lets images or text run as PHP', 'empedia-shield' ),
			'webshell_filename' => __( 'File name of a well-known web shell', 'empedia-shield' ),
			'hidden_php'       => __( 'Hidden PHP file', 'empedia-shield' ),
		);

		echo '<div class="empedia-card"><h2>' . esc_html__( 'File check', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Compares WordPress and your plugins from wordpress.org with the official checksums, looks for PHP files in the uploads folder and searches code without official checksums for well-known backdoor patterns. Only paths are stored and reported – never file contents. Findings are hints to check, not proof of an infection.', 'empedia-shield' ) . '</p>';
		echo '<p><button type="button" class="button button-primary" id="empedia-files-start"' . disabled( $running, true, false ) . '>' . esc_html__( 'Check files now', 'empedia-shield' ) . '</button> <span id="empedia-files-msg" class="description">' . ( $running ? esc_html__( 'The check is running …', 'empedia-shield' ) : '' ) . '</span></p>';
		if ( $result ) {
			/* translators: 1: time ago, 2: number of files */
			echo '<p class="description">' . esc_html( sprintf( __( 'Last check %1$s ago, %2$d files searched for patterns.', 'empedia-shield' ), human_time_diff( (int) $result['finished'], time() ), (int) $result['sig_scanned'] ) ) . '</p>';
			if ( 'ok' !== $result['core']['status'] ) {
				echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The official checksums for this WordPress version could not be loaded, so WordPress files were not compared.', 'empedia-shield' ) . '</p></div>';
			}
			if ( $result['plugins']['no_checksums'] ) {
				/* translators: %d: number of plugins */
				echo '<p class="description">' . esc_html( sprintf( __( '%d plugins have no official checksums (premium or custom plugins); their code was searched for patterns instead.', 'empedia-shield' ), count( $result['plugins']['no_checksums'] ) ) ) . '</p>';
			}
			if ( ! empty( $result['sig_truncated'] ) ) {
				echo '<div class="notice notice-info inline"><p>' . esc_html__( 'The pattern search stopped at the maximum number of files; large installations are not searched completely.', 'empedia-shield' ) . '</p></div>';
			}
		} else {
			echo '<p class="description">' . esc_html__( 'No check has run yet.', 'empedia-shield' ) . '</p>';
		}
		echo '</div>';

		if ( $result ) {
			$vis = Empedia_Cloud_Scanner::visible_items( $result );
			$any = false;
			foreach ( $kinds as $kind => $title ) {
				if ( empty( $vis[ $kind ] ) ) {
					continue;
				}
				$any = true;
				echo '<div class="empedia-card"><h2>' . esc_html( $title ) . ' (' . count( $vis[ $kind ] ) . ')</h2><table class="widefat striped"><tbody>';
				foreach ( array_slice( $vis[ $kind ], 0, 100 ) as $it ) {
					$path = is_array( $it ) ? ( isset( $it['slug'] ) ? $it['slug'] . '/' . $it['path'] : $it['path'] ) : $it;
					echo '<tr><td><code>' . esc_html( $path ) . '</code>';
					if ( is_array( $it ) && isset( $it['rule'], $rules[ $it['rule'] ] ) ) {
						echo '<br><span class="description">' . esc_html( $rules[ $it['rule'] ] ) . '</span>';
					}
					echo '</td><td style="text-align:right;white-space:nowrap">';
					self::item_form( 'empedia_cloud_files_ignore', Empedia_Cloud_Scanner::item_key( $kind, $it ), __( 'Mark as expected', 'empedia-shield' ) );
					echo '</td></tr>';
				}
				echo '</tbody></table></div>';
			}
			if ( ! $any ) {
				echo '<div class="empedia-card"><p><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> ' . esc_html__( 'Nothing conspicuous found. This is no guarantee: the check only detects known patterns and deviations from official files.', 'empedia-shield' ) . '</p></div>';
			}
		}

		$ign = Empedia_Cloud_Scanner::ignored();
		if ( $ign ) {
			echo '<div class="empedia-card"><h2>' . esc_html__( 'Marked as expected', 'empedia-shield' ) . '</h2><table class="widefat striped"><tbody>';
			foreach ( $ign as $key ) {
				echo '<tr><td><code>' . esc_html( preg_replace( '/#[0-9a-fx]+$/', '', $key ) ) . '</code></td><td style="text-align:right">';
				self::item_form( 'empedia_cloud_files_unignore', $key, __( 'Show again', 'empedia-shield' ) );
				echo '</td></tr>';
			}
			echo '</tbody></table></div>';
		}

		$auto = Empedia_Cloud_Scanner::settings()['auto'];
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Automatic check', 'empedia-shield' ) . '</h2><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_files_settings">';
		wp_nonce_field( 'empedia_cloud_files_settings' );
		echo '<p><label><input type="checkbox" name="auto" value="1"' . checked( $auto, true, false ) . '> ' . esc_html__( 'Check once a day in the background (in small steps, not while the server is busy)', 'empedia-shield' ) . '</label></p>';
		echo '<p><button type="submit" class="button">' . esc_html__( 'Save', 'empedia-shield' ) . '</button></p></form>';
		echo '<p class="description">' . esc_html__( 'Backup plugins can report a finished backup with: do_action( \'empedia_cloud_backup_done\' );', 'empedia-shield' ) . '</p></div>';
	}
}
