<?php
/**
 * Tab “Backups”: settings, start, list, download, restore, delete.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Backup_Admin {

	public static function init() {
		foreach ( array( 'settings', 'delete', 'download', 'restore', 'key', 'keyfetch', 'activate', 'rdelete', 'target_save', 'target_delete', 'target_toggle', 'target_test', 'target_connect' ) as $a ) {
			add_action( 'admin_post_empedia_cloud_backup_' . $a, array( __CLASS__, 'handle_' . $a ) );
		}
		add_action( 'load-toplevel_page_' . Empedia_Cloud_Connect::PAGE, array( __CLASS__, 'oauth_return' ) );
		add_action( 'wp_ajax_empedia_cloud_backup_start', array( __CLASS__, 'ajax_start' ) );
		add_action( 'wp_ajax_empedia_cloud_backup_poll', array( __CLASS__, 'ajax_poll' ) );
	}

	/** Capability check; every handler calls it first and then check_admin_referer() with its own nonce action. */
	private static function cap() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
	}

	private static function back() {
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'backups' ) );
		exit;
	}

	private static function id() {
		return isset( $_POST['id'] ) ? preg_replace( '/[^A-Za-z0-9\-]/', '', sanitize_text_field( wp_unslash( $_POST['id'] ) ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification -- only called by handlers that have run check_admin_referer().
	}

	public static function handle_settings() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_settings' );
		Empedia_Cloud_Backup::save_settings( wp_unslash( $_POST ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		Empedia_Cloud_Admin::flash( 'success', __( 'Settings saved.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_delete() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_delete' );
		Empedia_Cloud_Backup::delete( self::id() );
		Empedia_Cloud_Admin::flash( 'success', __( 'Backup deleted.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_download() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_download' );
		$e = Empedia_Cloud_Backup::find( self::id() );
		$f = $e ? Empedia_Cloud_Backup::path_of( $e ) : '';
		if ( ! $e || ! is_file( $f ) ) {
			self::back();
		}
		nocache_headers();
		header( 'Content-Type: application/octet-stream' );
		header( 'Content-Disposition: attachment; filename="' . basename( $e['file'] ) . '"' );
		header( 'Content-Length: ' . filesize( $f ) );
		while ( ob_get_level() ) {
			ob_end_clean();
		}
		readfile( $f ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		exit;
	}

	public static function handle_restore() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_restore' );
		$word = isset( $_POST['confirm'] ) ? strtoupper( trim( sanitize_text_field( wp_unslash( $_POST['confirm'] ) ) ) ) : '';
		if ( 'RESTORE' !== $word ) {
			Empedia_Cloud_Admin::flash( 'error', __( 'Please type RESTORE to confirm.', 'empedia-shield' ) );
			self::back();
		}
		$tid = isset( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : '';
		$r   = Empedia_Cloud_Restore::start( self::id(), $tid );
		if ( is_wp_error( $r ) ) {
			$msg = array(
				'busy'         => __( 'Another backup or restore is running.', 'empedia-shield' ),
				'missing'      => __( 'The backup file was not found.', 'empedia-shield' ),
				'url_mismatch' => __( 'This backup was made for a different site address and cannot be restored here.', 'empedia-shield' ),
			);
			Empedia_Cloud_Admin::flash( 'error', isset( $msg[ $r->get_error_code() ] ) ? $msg[ $r->get_error_code() ] : __( 'The restore could not be started.', 'empedia-shield' ) );
		}
		self::back();
	}

	public static function handle_key() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_key' );
		$k = isset( $_POST['key'] ) ? trim( sanitize_text_field( wp_unslash( $_POST['key'] ) ) ) : '';
		$ok = Empedia_Cloud_Backup::set_master_key( $k );
		Empedia_Cloud_Admin::flash( $ok ? 'success' : 'error', $ok ? __( 'Key saved.', 'empedia-shield' ) : __( 'The key is not valid.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_keyfetch() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_keyfetch' );
		$k = Empedia_Cloud_Bunny::fetch_key();
		if ( is_wp_error( $k ) || ! Empedia_Cloud_Backup::set_master_key( $k ) ) {
			Empedia_Cloud_Admin::flash( 'error', __( 'The key could not be loaded from EMPEDIAcloud.', 'empedia-shield' ) );
		} else {
			update_option( Empedia_Cloud_Bunny::ESCROW, hash( 'sha256', Empedia_Cloud_Backup::master_key() ), false );
			Empedia_Cloud_Admin::flash( 'success', __( 'The key was loaded from EMPEDIAcloud.', 'empedia-shield' ) );
		}
		self::back();
	}

	public static function handle_activate() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_activate' );
		$r = Empedia_Cloud_Bunny::activate();
		if ( is_wp_error( $r ) ) {
			Empedia_Cloud_Admin::flash( 'error', 'empedia_no_slot' === $r->get_error_code() ? __( 'You have no free storage package. Book one first.', 'empedia-shield' ) : $r->get_error_message() );
		} else {
			Empedia_Cloud_Admin::flash( 'success', __( 'The cloud storage is ready.', 'empedia-shield' ) );
		}
		self::back();
	}

	public static function handle_rdelete() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_rdelete' );
		$tid = isset( $_POST['target'] ) ? sanitize_key( wp_unslash( $_POST['target'] ) ) : 'cloud';
		$t   = Empedia_Cloud_Targets::get( $tid );
		$r   = $t ? $t->remove( self::id() ) : new WP_Error( 'target', 'target' );
		if ( $t ) {
			Empedia_Cloud_Targets::forget_listing( $tid );
		}
		Empedia_Cloud_Admin::flash( is_wp_error( $r ) ? 'error' : 'success', is_wp_error( $r ) ? __( 'The backup could not be deleted.', 'empedia-shield' ) : __( 'Backup deleted.', 'empedia-shield' ) );
		self::back();
	}

	/**
	 * Is the site connected and on the Pro level? Only the storage services that sign in through EMPEDIAcloud
	 * ( Google Drive, OneDrive, Dropbox, Box, pCloud ) need it, because they use the OAuth apps of EMPEDIAcloud.
	 * S3, WebDAV, FTP/FTPS and add-on targets work on the site alone.
	 */
	private static function pro() {
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			return false;
		}
		$st = Empedia_Cloud_Bunny::status();
		return ! is_wp_error( $st ) && isset( $st['tier'] ) && 'pro' === $st['tier'];
	}

	private static function oauth_class() {
		$f = EMPEDIA_CLOUD_DIR . 'includes/targets/class-empedia-target-oauth.php';
		if ( ! class_exists( 'Empedia_Cloud_Target_Oauth', false ) && is_file( $f ) ) {
			require_once $f;
		}
		return class_exists( 'Empedia_Cloud_Target_Oauth', false );
	}

	public static function handle_target_save() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_target_save' );
		$type  = isset( $_POST['type'] ) ? sanitize_key( wp_unslash( $_POST['type'] ) ) : '';
		$types = Empedia_Cloud_Targets::types();
		if ( ! isset( $types[ $type ] ) ) {
			self::back();
		}
		$cfg = array();
		foreach ( $types[ $type ]['fields'] as $k => $f ) {
			$v = isset( $_POST['f'][ $k ] ) ? wp_unslash( $_POST['f'][ $k ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			$cfg[ $k ] = 'textarea' === $f['type'] ? trim( (string) $v ) : sanitize_text_field( (string) $v );
			if ( 'checkbox' === $f['type'] ) {
				$cfg[ $k ] = ! empty( $v ) ? '1' : '';
			}
		}
		$id    = isset( $_POST['tid'] ) ? sanitize_key( wp_unslash( $_POST['tid'] ) ) : '';
		$label = isset( $_POST['label'] ) ? sanitize_text_field( wp_unslash( $_POST['label'] ) ) : '';
		$old   = $id ? Empedia_Cloud_Targets::form_values( $id ) : null;
		if ( $id && ! $old ) {
			$id = '';
		}
		$missing = array();
		foreach ( $types[ $type ]['fields'] as $k => $f ) {
			$have_old = $old && isset( $old['cfg'][ $k ] );
			$secret   = in_array( $k, array( 'password', 'secret', 'private_key' ), true );
			if ( ! empty( $f['required'] ) && '' === $cfg[ $k ] && ! ( $secret && $id ) ) {
				$missing[] = $f['label'];
			}
			unset( $have_old );
		}
		if ( $missing ) {
			/* translators: %s: field names */
			Empedia_Cloud_Admin::flash( 'error', sprintf( __( 'Please fill in: %s', 'empedia-shield' ), implode( ', ', $missing ) ) );
			self::back();
		}
		$id = Empedia_Cloud_Targets::save( $id, $type, '' !== $label ? $label : $types[ $type ]['label'], $cfg, true );
		$t  = Empedia_Cloud_Targets::instance( $id );
		$r  = $t ? $t->test() : new WP_Error( 'type', 'type' );
		if ( $t ) {
			$t->close();
		}
		Empedia_Cloud_Targets::mark( $id, is_wp_error( $r ) ? $r->get_error_code() : '' );
		if ( is_wp_error( $r ) ) {
			Empedia_Cloud_Admin::flash( 'error', sprintf( /* translators: %s: error code */ __( 'The target was saved, but the connection test failed (%s). Please check the details.', 'empedia-shield' ), $r->get_error_code() ) );
		} else {
			Empedia_Cloud_Admin::flash( 'success', __( 'The storage target works and is saved.', 'empedia-shield' ) );
		}
		self::back();
	}

	public static function handle_target_delete() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_target_delete' );
		Empedia_Cloud_Targets::remove( isset( $_POST['tid'] ) ? sanitize_key( wp_unslash( $_POST['tid'] ) ) : '' );
		Empedia_Cloud_Admin::flash( 'success', __( 'The storage target was removed. Backups stored there were not deleted.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_target_toggle() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_target_toggle' );
		$id = isset( $_POST['tid'] ) ? sanitize_key( wp_unslash( $_POST['tid'] ) ) : '';
		$l  = Empedia_Cloud_Targets::listing();
		if ( isset( $l[ $id ] ) ) {
			Empedia_Cloud_Targets::set_enabled( $id, ! $l[ $id ]['enabled'] );
		}
		self::back();
	}

	public static function handle_target_test() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_target_test' );
		$id = isset( $_POST['tid'] ) ? sanitize_key( wp_unslash( $_POST['tid'] ) ) : '';
		$l  = Empedia_Cloud_Targets::listing();
		if ( isset( $l[ $id ] ) && Empedia_Cloud_Targets::needs_addon( $l[ $id ]['type'] ) ) {
			$addon = Empedia_Cloud_Targets::addon_types();
			/* translators: %s: name of the add-on plugin */
			Empedia_Cloud_Admin::flash( 'error', sprintf( __( 'This target needs the add-on plugin “%s”. Install and activate it to use this target. Backups already stored there are not affected.', 'empedia-shield' ), $addon[ $l[ $id ]['type'] ]['addon'] ) );
			self::back();
		}
		$t  = Empedia_Cloud_Targets::instance( $id );
		$r  = $t ? $t->test() : new WP_Error( 'unreadable', 'unreadable' );
		if ( $t ) {
			$t->close();
		}
		Empedia_Cloud_Targets::mark( $id, is_wp_error( $r ) ? $r->get_error_code() : '' );
		Empedia_Cloud_Admin::flash( is_wp_error( $r ) ? 'error' : 'success', is_wp_error( $r ) ? sprintf( /* translators: %s: error code */ __( 'The connection test failed (%s).', 'empedia-shield' ), $r->get_error_code() ) : __( 'The connection works.', 'empedia-shield' ) );
		self::back();
	}

	/** Starts the sign-in at an online storage service ( through EMPEDIAcloud ). */
	public static function handle_target_connect() {
		self::cap();
		check_admin_referer( 'empedia_cloud_backup_target_connect' );
		$type = isset( $_POST['type'] ) ? sanitize_key( wp_unslash( $_POST['type'] ) ) : '';
		if ( ! self::pro() || ! isset( Empedia_Cloud_Targets::oauth_types()[ $type ] ) || ! self::oauth_class() ) {
			Empedia_Cloud_Admin::flash( 'error', __( 'This storage service is not available for your account yet.', 'empedia-shield' ) );
			self::back();
		}
		$url = Empedia_Cloud_Target_Oauth::begin( $type, add_query_arg( 'empedia_provider', $type, Empedia_Cloud_Admin::tab_url( 'backups' ) ) );
		if ( is_wp_error( $url ) ) {
			Empedia_Cloud_Admin::flash( 'error', $url->get_error_message() );
			self::back();
		}
		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect -- the sign-in page of the storage service
		exit;
	}

	/** The browser comes back from the storage service ( before any output ). */
	public static function oauth_return() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification -- the state is bound to this site and checked by EMPEDIAcloud
		if ( isset( $_GET['empedia_oauth_error'] ) ) {
			Empedia_Cloud_Admin::flash( 'error', __( 'The connection to the storage service was cancelled or failed.', 'empedia-shield' ) );
			wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'backups' ) );
			exit;
		}
		if ( ! isset( $_GET['empedia_oauth'] ) || ! self::oauth_class() ) {
			return;
		}
		$state = sanitize_text_field( wp_unslash( $_GET['empedia_oauth'] ) );
		$type  = isset( $_GET['empedia_provider'] ) ? sanitize_key( wp_unslash( $_GET['empedia_provider'] ) ) : '';
		// phpcs:enable
		$r = Empedia_Cloud_Target_Oauth::claim( $state );
		if ( is_wp_error( $r ) || ! isset( Empedia_Cloud_Targets::oauth_types()[ $type ] ) ) {
			Empedia_Cloud_Admin::flash( 'error', is_wp_error( $r ) ? $r->get_error_message() : __( 'The connection to the storage service failed.', 'empedia-shield' ) );
		} else {
			$id = Empedia_Cloud_Targets::save( '', $type, Empedia_Cloud_Targets::oauth_types()[ $type ] . ( ! empty( $r['account'] ) ? ' (' . sanitize_text_field( $r['account'] ) . ')' : '' ), $r + array( 'path' => 'EMPEDIAcloud Backups' ), true );
			$t  = Empedia_Cloud_Targets::instance( $id );
			$ok = $t ? $t->test() : new WP_Error( 'type', 'type' );
			Empedia_Cloud_Targets::mark( $id, is_wp_error( $ok ) ? $ok->get_error_code() : '' );
			Empedia_Cloud_Admin::flash( is_wp_error( $ok ) ? 'error' : 'success', is_wp_error( $ok ) ? __( 'The account was connected, but a test file could not be stored.', 'empedia-shield' ) : __( 'The storage service is connected.', 'empedia-shield' ) );
		}
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'backups' ) );
		exit;
	}

	public static function ajax_start() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) || ! check_ajax_referer( 'empedia_cloud_backup', 'nonce', false ) ) {
			wp_send_json_error( array(), 403 );
		}
		if ( ! Empedia_Cloud_Backup::start( true ) && Empedia_Cloud_Backup::running() === false ) {
			$e = get_option( 'empedia_backup_start_error', '' );
			if ( $e ) {
				wp_send_json_error( array( 'message' => (string) $e ), 400 );
			}
		}
		wp_send_json_success( self::progress() );
	}

	public static function ajax_poll() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) || ! check_ajax_referer( 'empedia_cloud_backup', 'nonce', false ) ) {
			wp_send_json_error( array(), 403 );
		}
		// WP-Cron needs visits; keep the work going while this page is open.
		if ( Empedia_Cloud_Backup::running() ) {
			Empedia_Cloud_Backup::tick();
		} elseif ( Empedia_Cloud_Restore::running() ) {
			Empedia_Cloud_Restore::tick();
		}
		wp_send_json_success( self::progress() );
	}

	private static function progress() {
		$b = Empedia_Cloud_Backup::progress();
		$r = Empedia_Cloud_Restore::progress();
		return array(
			'running' => $b['running'] || $r['running'],
			'label'   => $b['running'] ? $b['label'] : $r['label'],
			'restore' => (bool) $r['running'],
		);
	}

	private static function render_cloud( array $set ) {
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Cloud storage', 'empedia-shield' ) . '</h2>';
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			echo '<p>' . esc_html__( 'Connect this site with EMPEDIAcloud to store backups in the cloud.', 'empedia-shield' ) . '</p></div>';
			return;
		}
		$st = Empedia_Cloud_Bunny::status();
		if ( is_wp_error( $st ) ) {
			echo '<p>' . esc_html__( 'The storage state could not be loaded. Please try again later.', 'empedia-shield' ) . '</p></div>';
			return;
		}
		$z = isset( $st['zone'] ) ? $st['zone'] : null;
		if ( $z ) {
			$quota = (float) $z['quota_gb'] * 1073741824;
			$used  = (float) $z['used_bytes'];
			printf(
				'<p>%s</p><progress value="%d" max="%d" style="width:100%%;max-width:420px"></progress>',
				esc_html( sprintf( /* translators: 1: used, 2: package size */ __( '%1$s of %2$s used', 'empedia-shield' ), size_format( $used ), size_format( $quota ) ) ),
				(int) min( $used, $quota ),
				(int) max( 1, $quota )
			);
			if ( 'grace' === $z['status'] ) {
				echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The storage package ended. Your backups are kept for a short time and will then be deleted. Book a package again to keep them.', 'empedia-shield' ) . '</p></div>';
			}
			if ( 'active' === $z['status'] ) {
				$l = Empedia_Cloud_Bunny::list_backups();
				if ( is_wp_error( $l ) || ! $l ) {
					echo '<p>' . esc_html__( 'No backups in the cloud yet.', 'empedia-shield' ) . '</p>';
				} else {
					echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Date', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Size', 'empedia-shield' ) . '</th><th></th></tr></thead><tbody>';
					foreach ( $l as $m ) {
						echo '<tr><td>' . esc_html( Empedia_Cloud_Admin::fmt_date( strtotime( $m['created'] ) ) ) . '</td><td>' . esc_html( size_format( (int) $m['size'] ) ) . '</td><td><div class="empedia-actions">';
						echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-restore" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_restore"><input type="hidden" name="id" value="' . esc_attr( $m['id'] ) . '"><input type="hidden" name="target" value="cloud">';
						wp_nonce_field( 'empedia_cloud_backup_restore' );
						echo '<input type="hidden" name="confirm" value="RESTORE"><button type="submit" class="button button-small">' . esc_html__( 'Restore', 'empedia-shield' ) . '</button></form>';
						self::post_form( 'empedia_cloud_backup_rdelete', $m['id'], __( 'Delete', 'empedia-shield' ), 'button button-small button-link-delete empedia-del' );
						echo '</div></td></tr>';
					}
					echo '</tbody></table>';
				}
			}
		} elseif ( ! empty( $st['free_slots'] ) ) {
			echo '<p>' . esc_html__( 'You have a storage package that is not used yet.', 'empedia-shield' ) . '</p>';
			self::post_form( 'empedia_cloud_backup_activate', '', __( 'Set up the cloud storage', 'empedia-shield' ), 'button button-primary' );
		} else {
			echo '<p>' . esc_html__( 'Store your encrypted backups safely outside of your server, in a European data center. Choose a storage package in EMPEDIAcloud.', 'empedia-shield' ) . '</p>';
			if ( ! empty( $st['plans_url'] ) ) {
				printf( '<p><a class="button button-primary" href="%s" target="_blank" rel="noopener noreferrer">%s</a></p>', esc_url( $st['plans_url'] ), esc_html__( 'Choose a storage package', 'empedia-shield' ) );
			}
		}
		echo '</div>';
	}

	private static function field_html( $name, array $f, $val ) {
		$n = 'f[' . $name . ']';
		if ( 'checkbox' === $f['type'] ) {
			return '<label><input type="checkbox" name="' . esc_attr( $n ) . '" value="1"' . checked( ! empty( $val ), true, false ) . '> ' . esc_html( $f['label'] ) . '</label>';
		}
		$h = '<label>' . esc_html( $f['label'] ) . ( ! empty( $f['required'] ) ? ' *' : '' ) . '<br>';
		if ( 'textarea' === $f['type'] ) {
			$h .= '<textarea name="' . esc_attr( $n ) . '" rows="4" class="large-text code" autocomplete="off">' . esc_textarea( (string) $val ) . '</textarea>';
		} else {
			$h .= '<input type="' . ( 'password' === $f['type'] ? 'password' : 'text' ) . '" name="' . esc_attr( $n ) . '" value="' . esc_attr( (string) $val ) . '" class="regular-text" autocomplete="off"' . ( 'password' === $f['type'] ? ' placeholder="' . esc_attr__( 'Leave empty to keep the saved value', 'empedia-shield' ) . '"' : '' ) . '>';
		}
		return $h . '</label>' . ( ! empty( $f['help'] ) ? '<br><span class="description">' . esc_html( $f['help'] ) . '</span>' : '' );
	}

	private static function target_form( $type, array $def, $tid = '', $label = '', array $cfg = array() ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-target-form" data-type="' . esc_attr( $type ) . '"' . ( $tid ? '' : ' style="display:none"' ) . '>';
		echo '<input type="hidden" name="action" value="empedia_cloud_backup_target_save"><input type="hidden" name="type" value="' . esc_attr( $type ) . '"><input type="hidden" name="tid" value="' . esc_attr( $tid ) . '">';
		wp_nonce_field( 'empedia_cloud_backup_target_save' );
		echo '<p><label>' . esc_html__( 'Name', 'empedia-shield' ) . '<br><input type="text" name="label" value="' . esc_attr( $label ) . '" class="regular-text" placeholder="' . esc_attr( $def['label'] ) . '"></label></p>';
		foreach ( $def['fields'] as $k => $f ) {
			echo '<p>' . self::field_html( $k, $f, isset( $cfg[ $k ] ) ? $cfg[ $k ] : '' ) . '</p>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save and test', 'empedia-shield' ) . '</button></p></form>';
	}

	private static function render_targets() {
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Your own storage targets', 'empedia-shield' ) . '</h2>';
		$types = Empedia_Cloud_Targets::types();
		$pro   = self::pro();
		echo '<p>' . esc_html__( 'Send your encrypted backups to your own server or cloud account: S3-compatible storage, Nextcloud or another WebDAV server, an FTP or FTPS server, and with the add-on “EMPEDIA Shield SFTP” an SFTP server. These targets work on this site alone, without an EMPEDIAcloud account. The files are encrypted on your site before they leave it.', 'empedia-shield' ) . '</p>';
		$list = Empedia_Cloud_Targets::listing();
		if ( $list ) {
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Name', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Status', 'empedia-shield' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $list as $id => $t ) {
				if ( Empedia_Cloud_Targets::needs_addon( $t['type'] ) ) {
					$addon  = Empedia_Cloud_Targets::addon_types();
					/* translators: %s: name of the add-on plugin */
					$status = esc_html( sprintf( __( 'This target needs the add-on plugin “%s”. Install and activate it to use this target. Backups already stored there are not affected.', 'empedia-shield' ), $addon[ $t['type'] ]['addon'] ) );
				} elseif ( ! $t['ok'] ) {
					$status = esc_html__( 'The saved details cannot be read. Please enter them again.', 'empedia-shield' );
				} elseif ( 'reauth_required' === $t['error'] ) {
					$status = esc_html__( 'The connection was revoked or expired. Please connect the account again.', 'empedia-shield' );
				} elseif ( $t['error'] ) {
					$status = esc_html( sprintf( /* translators: %s: error code */ __( 'Last test failed (%s)', 'empedia-shield' ), $t['error'] ) );
				} else {
					$status = $t['tested'] ? esc_html__( 'Works', 'empedia-shield' ) : esc_html__( 'Not tested yet', 'empedia-shield' );
				}
				if ( ! $t['enabled'] ) {
					$status .= ' · ' . esc_html__( 'Paused', 'empedia-shield' );
				}
				echo '<tr><td>' . esc_html( $t['label'] ) . '</td><td>' . $status . '</td><td>'; // phpcs:ignore WordPress.Security.EscapeOutput
				foreach ( array( 'target_test' => __( 'Test', 'empedia-shield' ), 'target_toggle' => $t['enabled'] ? __( 'Pause', 'empedia-shield' ) : __( 'Resume', 'empedia-shield' ) ) as $a => $l ) {
					echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_' . esc_attr( $a ) . '"><input type="hidden" name="tid" value="' . esc_attr( $id ) . '">';
					wp_nonce_field( 'empedia_cloud_backup_' . $a );
					echo '<button type="submit" class="button-link">' . esc_html( $l ) . '</button></form> | ';
				}
				if ( isset( $types[ $t['type'] ] ) ) {
					echo '<a href="' . esc_url( add_query_arg( 'edit', $id, Empedia_Cloud_Admin::tab_url( 'backups' ) ) ) . '">' . esc_html__( 'Edit', 'empedia-shield' ) . '</a> | ';
				}
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-del-form" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_target_delete"><input type="hidden" name="tid" value="' . esc_attr( $id ) . '">';
				wp_nonce_field( 'empedia_cloud_backup_target_delete' );
				echo '<button type="submit" class="button-link-delete empedia-del">' . esc_html__( 'Remove', 'empedia-shield' ) . '</button></form></td></tr>';
			}
			echo '</tbody></table>';
		}
		// phpcs:ignore WordPress.Security.NonceVerification
		$edit = isset( $_GET['edit'] ) ? sanitize_key( wp_unslash( $_GET['edit'] ) ) : '';
		$ev   = $edit ? Empedia_Cloud_Targets::form_values( $edit ) : null;
		if ( $ev && isset( $types[ $ev['type'] ] ) ) {
			echo '<h3>' . esc_html( sprintf( /* translators: %s: target name */ __( 'Edit %s', 'empedia-shield' ), $ev['label'] ) ) . '</h3>';
			self::target_form( $ev['type'], $types[ $ev['type'] ], $edit, $ev['label'], $ev['cfg'] );
		}
		echo '<h3>' . esc_html__( 'Add a storage target', 'empedia-shield' ) . '</h3>';
		echo '<p><select id="empedia-target-type"><option value="">' . esc_html__( 'Choose …', 'empedia-shield' ) . '</option>';
		foreach ( $types as $k => $d ) {
			echo '<option value="' . esc_attr( $k ) . '">' . esc_html( $d['label'] ) . '</option>';
		}
		echo '</select></p>';
		foreach ( $types as $k => $d ) {
			self::target_form( $k, $d );
		}
		echo '<h3>' . esc_html__( 'Online storage with sign-in', 'empedia-shield' ) . '</h3>';
		if ( ! $pro ) {
			echo '<p class="description">' . esc_html( Empedia_Cloud_Client::is_connected()
				? __( 'Google Drive, OneDrive, Dropbox, Box and pCloud are part of the Pro plan of EMPEDIAcloud: the sign-in runs through EMPEDIAcloud.', 'empedia-shield' )
				: __( 'Google Drive, OneDrive, Dropbox, Box and pCloud sign in through EMPEDIAcloud: they need a connection of this site to EMPEDIAcloud and its Pro plan. All targets above work without it.', 'empedia-shield' ) ) . '</p>';
		}
		echo '<p class="empedia-oauth-buttons">';
		if ( $pro && self::oauth_class() ) {
			foreach ( Empedia_Cloud_Targets::oauth_types() as $k => $label ) {
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_target_connect"><input type="hidden" name="type" value="' . esc_attr( $k ) . '">';
				wp_nonce_field( 'empedia_cloud_backup_target_connect' );
				/* translators: %s: name of an online storage service */
				echo '<button type="submit" class="button">' . esc_html( sprintf( __( 'Connect %s', 'empedia-shield' ), $label ) ) . '</button></form> ';
			}
		}
		echo '</p>';
		// Backups in the targets.
		foreach ( Empedia_Cloud_Targets::active() as $tid => $t ) {
			if ( 'cloud' === $tid ) {
				continue;
			}
			$l = Empedia_Cloud_Targets::backups( $t );
			$t->close();
			echo '<h3>' . esc_html( Empedia_Cloud_Targets::label_of( $tid ) ) . '</h3>';
			if ( is_wp_error( $l ) || ! $l ) {
				echo '<p>' . esc_html( is_wp_error( $l ) ? __( 'The backups in this target could not be listed.', 'empedia-shield' ) : __( 'No backups in this target yet.', 'empedia-shield' ) ) . '</p>';
				continue;
			}
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Date', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Size', 'empedia-shield' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $l as $m ) {
				echo '<tr><td>' . esc_html( Empedia_Cloud_Admin::fmt_date( strtotime( $m['created'] ) ) ) . '</td><td>' . esc_html( size_format( (int) $m['size'] ) ) . '</td><td><div class="empedia-actions">';
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-restore" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_restore"><input type="hidden" name="id" value="' . esc_attr( $m['id'] ) . '"><input type="hidden" name="target" value="' . esc_attr( $tid ) . '">';
				wp_nonce_field( 'empedia_cloud_backup_restore' );
				echo '<input type="hidden" name="confirm" value="RESTORE"><button type="submit" class="button button-small">' . esc_html__( 'Restore', 'empedia-shield' ) . '</button></form>';
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_rdelete"><input type="hidden" name="id" value="' . esc_attr( $m['id'] ) . '"><input type="hidden" name="target" value="' . esc_attr( $tid ) . '">';
				wp_nonce_field( 'empedia_cloud_backup_rdelete' );
				echo '<button type="submit" class="button button-small button-link-delete empedia-del">' . esc_html__( 'Delete', 'empedia-shield' ) . '</button></form>';
				echo '</div></td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';
	}

	private static function post_form( $action, $id, $label, $class = 'button-link', $extra = '' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline"' . $extra . '>'; // phpcs:ignore WordPress.Security.EscapeOutput
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '"><input type="hidden" name="id" value="' . esc_attr( $id ) . '">';
		wp_nonce_field( $action );
		echo '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	public static function render_tab() {
		wp_enqueue_script( 'empedia-cloud-backup', EMPEDIA_CLOUD_URL_BASE . 'assets/backup.js', array(), EMPEDIA_CLOUD_VERSION, true );
		wp_localize_script(
			'empedia-cloud-backup',
			'EmpediaBackup',
			array(
				'ajax'    => admin_url( 'admin-ajax.php' ),
				'nonce'   => wp_create_nonce( 'empedia_cloud_backup' ),
				'running' => Empedia_Cloud_Backup::running() || Empedia_Cloud_Restore::running(),
				'i18n'    => array(
					'starting' => __( 'Starting the backup …', 'empedia-shield' ),
					'error'    => __( 'The request failed. Please try again.', 'empedia-shield' ),
					'confirm'  => __( 'Restore this backup? Content created since then will be lost. A safety copy of the current database is saved first. You may be signed out afterwards.', 'empedia-shield' ),
					'delete'   => __( 'Delete this backup?', 'empedia-shield' ),
				),
			)
		);
		$set  = Empedia_Cloud_Backup::settings();
		$list = Empedia_Cloud_Backup::index();
		$rs   = Empedia_Cloud_Restore::state();
		$bs   = Empedia_Cloud_Backup::state();

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Backups', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Backups are stored on this server in a folder that is closed for web access. Backups on the same server do not protect you if the server is lost: download important ones or connect an external target.', 'empedia-shield' ) . '</p>';
		if ( $bs && 'failed' === $bs['phase'] ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'The last backup failed.', 'empedia-shield' ) . '</p></div>';
		}
		if ( $bs && ! empty( $bs['remote_error'] ) ) {
			$names = array();
			foreach ( explode( ',', $bs['remote_error'] ) as $tid ) {
				$names[] = Empedia_Cloud_Targets::label_of( $tid );
			}
			/* translators: %s: names of storage targets */
			echo '<div class="notice notice-error inline"><p>' . esc_html( sprintf( __( 'The last upload failed for: %s. The backup is still available on this server.', 'empedia-shield' ), implode( ', ', $names ) ) ) . '</p></div>';
		}
		if ( $rs && 'done' === $rs['phase'] && ! empty( $rs['finished'] ) && time() - (int) $rs['finished'] < DAY_IN_SECONDS ) {
			echo '<div class="notice notice-success inline"><p>' . esc_html__( 'A backup was restored.', 'empedia-shield' ) . '</p></div>';
		} elseif ( $rs && 'failed' === $rs['phase'] && ! empty( $rs['finished'] ) && time() - (int) $rs['finished'] < DAY_IN_SECONDS ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html__( 'The restore failed. Your site was not changed beyond the safety copy.', 'empedia-shield' ) . '</p></div>';
		}
		echo '<p><button type="button" class="button button-primary" id="empedia-backup-start">' . esc_html__( 'Back up now', 'empedia-shield' ) . '</button> <span id="empedia-backup-msg" class="description" role="status"></span></p></div>';

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Saved backups', 'empedia-shield' ) . '</h2>';
		if ( ! $list ) {
			echo '<p>' . esc_html__( 'No backups yet.', 'empedia-shield' ) . '</p>';
		} else {
			$scopes = array(
				'both'  => __( 'Files and database', 'empedia-shield' ),
				'files' => __( 'Files', 'empedia-shield' ),
				'db'    => __( 'Database', 'empedia-shield' ),
			);
			echo '<table class="widefat striped"><thead><tr><th>' . esc_html__( 'Date', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Content', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Size', 'empedia-shield' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( $list as $e ) {
				echo '<tr><td>' . esc_html( Empedia_Cloud_Admin::fmt_date( (int) $e['created'] ) ) . '</td><td>' . esc_html( isset( $scopes[ $e['scope'] ] ) ? $scopes[ $e['scope'] ] : $e['scope'] );
				if ( ! empty( $e['encrypted'] ) ) {
					echo ' <span title="' . esc_attr__( 'Encrypted', 'empedia-shield' ) . '" class="dashicons dashicons-lock"></span>';
				}
				echo '</td><td>' . esc_html( size_format( (int) $e['size'] ) ) . '</td><td><div class="empedia-actions">';
				self::post_form( 'empedia_cloud_backup_download', $e['id'], __( 'Download', 'empedia-shield' ), 'button button-small' );
				echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" class="empedia-restore" style="display:inline"><input type="hidden" name="action" value="empedia_cloud_backup_restore"><input type="hidden" name="id" value="' . esc_attr( $e['id'] ) . '">';
				wp_nonce_field( 'empedia_cloud_backup_restore' );
				echo '<input type="hidden" name="confirm" value="RESTORE"><button type="submit" class="button button-small">' . esc_html__( 'Restore', 'empedia-shield' ) . '</button></form>';
				self::post_form( 'empedia_cloud_backup_delete', $e['id'], __( 'Delete', 'empedia-shield' ), 'button button-small button-link-delete empedia-del' );
				echo '</div></td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';

		self::render_cloud( $set );
		self::render_targets();

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Settings', 'empedia-shield' ) . '</h2>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_backup_settings">';
		wp_nonce_field( 'empedia_cloud_backup_settings' );
		echo '<table class="form-table"><tr><th>' . esc_html__( 'Content', 'empedia-shield' ) . '</th><td><select name="scope">';
		foreach ( array( 'both' => __( 'Files and database', 'empedia-shield' ), 'files' => __( 'Files only', 'empedia-shield' ), 'db' => __( 'Database only', 'empedia-shield' ) ) as $k => $l ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $k ), selected( $set['scope'], $k, false ), esc_html( $l ) );
		}
		echo '</select></td></tr><tr><th>' . esc_html__( 'Automatic backup', 'empedia-shield' ) . '</th><td><select name="schedule">';
		foreach ( array( 'off' => __( 'Off', 'empedia-shield' ), 'daily' => __( 'Daily', 'empedia-shield' ), 'weekly' => __( 'Weekly (Sundays)', 'empedia-shield' ) ) as $k => $l ) {
			printf( '<option value="%s"%s>%s</option>', esc_attr( $k ), selected( $set['schedule'], $k, false ), esc_html( $l ) );
		}
		echo '</select></td></tr><tr><th>' . esc_html__( 'Keep the last', 'empedia-shield' ) . '</th><td><input type="number" name="keep" min="1" max="30" value="' . esc_attr( $set['keep'] ) . '" class="small-text"> ' . esc_html__( 'backups', 'empedia-shield' ) . '</td></tr>';
		echo '<tr><th>' . esc_html__( 'Encryption', 'empedia-shield' ) . '</th><td><label><input type="checkbox" name="encrypt" value="1"' . checked( $set['encrypt'], true, false ) . '> ' . esc_html__( 'Encrypt new backups', 'empedia-shield' ) . '</label><p class="description">' . esc_html__( 'Without the key an encrypted backup cannot be opened. Save the key below somewhere safe.', 'empedia-shield' ) . '</p></td></tr>';
		if ( Empedia_Cloud_Targets::active() ) {
			echo '<tr><th>' . esc_html__( 'Storage targets', 'empedia-shield' ) . '</th><td><label><input type="checkbox" name="remote" value="1"' . checked( $set['remote'], true, false ) . '> ' . esc_html__( 'Also upload backups to my storage targets (always encrypted)', 'empedia-shield' ) . '</label><br>' . esc_html__( 'Keep the last', 'empedia-shield' ) . ' <input type="number" name="keep_remote" min="1" max="60" value="' . esc_attr( $set['keep_remote'] ) . '" class="small-text"> ' . esc_html__( 'backups in each target', 'empedia-shield' ) . '</td></tr>';
		}
		echo '<tr><th>' . esc_html__( 'Exclude folders', 'empedia-shield' ) . '</th><td><textarea name="exclude" rows="3" class="large-text code" placeholder="wp-content/cache">' . esc_textarea( $set['exclude'] ) . '</textarea><p class="description">' . esc_html__( 'One path per line, relative to the WordPress folder. Cache folders and other backups are always left out.', 'empedia-shield' ) . '</p></td></tr></table>';
		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save settings', 'empedia-shield' ) . '</button></p></form></div>';

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Encryption key', 'empedia-shield' ) . '</h2><p>' . esc_html__( 'This key opens your encrypted backups. Keep a copy outside this server.', 'empedia-shield' ) . '</p>';
		echo '<p><code id="empedia-backup-key" style="user-select:all">' . esc_html( base64_encode( Empedia_Cloud_Backup::master_key() ) ) . '</code></p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_backup_key">';
		wp_nonce_field( 'empedia_cloud_backup_key' );
		echo '<input type="text" name="key" class="regular-text code" autocomplete="off" placeholder="' . esc_attr__( 'Enter a saved key (e.g. after moving the site)', 'empedia-shield' ) . '"> <button type="submit" class="button">' . esc_html__( 'Use this key', 'empedia-shield' ) . '</button></form>';
		if ( Empedia_Cloud_Bunny::has_zone() ) {
			echo '<p class="description">' . esc_html__( 'With a cloud storage your key is also kept safely in EMPEDIAcloud, so you can restore your site on a new server.', 'empedia-shield' ) . '</p>';
			self::post_form( 'empedia_cloud_backup_keyfetch', '', __( 'Load the key from EMPEDIAcloud', 'empedia-shield' ), 'button' );
		}
		echo '</div>';
	}
}
