<?php
/**
 * Change watcher: reports important changes ( new administrator, plugins and themes installed, activated or deleted,
 * WordPress updated, scanner findings, finished or failed backups, finished restores ) to EMPEDIAcloud shortly after they happen.
 *
 * Only technical facts are sent: the type of the change and, for plugins and themes, the folder name and version.
 * Never user names, e-mail addresses or any content. Nothing is queued while the site is not connected.
 *
 * Backup plugins can report a finished backup with:  do_action( 'empedia_cloud_backup_done' );
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Watch {

	const QUEUE     = 'empedia_cloud_events';
	const HOOK_SEND = 'empedia_cloud_events_send';
	const MAX       = 50;

	public static function init() {
		add_action( self::HOOK_SEND, array( __CLASS__, 'flush' ) );
		add_action( 'set_user_role', array( __CLASS__, 'on_role' ), 10, 3 );
		add_action( 'add_user_role', array( __CLASS__, 'on_add_role' ), 10, 2 );
		add_action( 'grant_super_admin', array( __CLASS__, 'on_super' ) );
		add_action( 'activated_plugin', array( __CLASS__, 'on_plugin_activated' ) );
		add_action( 'deactivated_plugin', array( __CLASS__, 'on_plugin_deactivated' ) );
		add_action( 'deleted_plugin', array( __CLASS__, 'on_plugin_deleted' ), 10, 2 );
		add_action( 'switch_theme', array( __CLASS__, 'on_theme' ) );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'on_upgrade' ), 10, 2 );
		add_action( '_core_updated_successfully', array( __CLASS__, 'on_core_updated' ) );
		add_action( 'empedia_cloud_backup_done', array( __CLASS__, 'on_backup' ) );
		add_action( 'empedia_cloud_backup_failed', array( __CLASS__, 'on_backup_failed' ) );
		add_action( 'empedia_cloud_restore_done', array( __CLASS__, 'on_restore' ) );
	}

	/** Adds an event and sends it in a few seconds ( through WP-Cron, never during the request ). */
	public static function record( $type, $detail = array() ) {
		if ( ! Empedia_Cloud_Client::is_connected() || get_option( 'empedia_cloud_token_invalid' ) ) {
			return;
		}
		$q   = get_option( self::QUEUE, array() );
		$q   = is_array( $q ) ? $q : array();
		$q[] = array( 't' => $type, 'at' => time(), 'd' => $detail );
		update_option( self::QUEUE, array_slice( $q, -self::MAX ), false );
		if ( ! wp_next_scheduled( self::HOOK_SEND ) ) {
			wp_schedule_single_event( time() + 8, self::HOOK_SEND );
		}
	}

	public static function flush() {
		$q = get_option( self::QUEUE, array() );
		if ( ! is_array( $q ) || ! $q || ! Empedia_Cloud_Client::is_connected() ) {
			return;
		}
		$sent = array_values( $q );
		$res  = Empedia_Cloud_Client::request( 'POST', '/events', array( 'events' => $sent ), true, 10 );
		if ( is_wp_error( $res ) ) {
			$data = $res->get_error_data();
			if ( ! empty( $data['status'] ) && $data['status'] < 500 && 429 !== (int) $data['status'] ) {
				delete_option( self::QUEUE ); // refused for good ( e.g. site idle ): do not keep trying
			} elseif ( ! wp_next_scheduled( self::HOOK_SEND ) ) {
				wp_schedule_single_event( time() + 10 * MINUTE_IN_SECONDS, self::HOOK_SEND );
			}
			return;
		}
		// Only what was sent is removed ( events recorded during the request stay ).
		$now = get_option( self::QUEUE, array() );
		$now = is_array( $now ) ? array_slice( $now, count( $sent ) ) : array();
		if ( $now ) {
			update_option( self::QUEUE, $now, false );
			if ( ! wp_next_scheduled( self::HOOK_SEND ) ) {
				wp_schedule_single_event( time() + 8, self::HOOK_SEND );
			}
		} else {
			delete_option( self::QUEUE );
		}
	}

	/* ------------------------------------------------------------------ hooks */

	/** @var array<int,bool> users already reported in this request ( one change fires several hooks ) */
	private static $admin_seen = array();

	public static function on_role( $user_id, $role, $old ) {
		if ( 'administrator' === $role && ! in_array( 'administrator', (array) $old, true ) && empty( self::$admin_seen[ $user_id ] ) ) {
			self::$admin_seen[ $user_id ] = true;
			self::record( 'admin_added', array( 'via' => empty( $old ) ? 'new' : 'role' ) );
		}
	}

	public static function on_add_role( $user_id, $role ) {
		if ( 'administrator' === $role && empty( self::$admin_seen[ $user_id ] ) ) {
			self::$admin_seen[ $user_id ] = true;
			self::record( 'admin_added', array( 'via' => 'role' ) );
		}
	}

	public static function on_super( $user_id ) {
		self::record( 'admin_added', array( 'via' => 'super' ) );
	}

	private static function plugin_detail( $file ) {
		$slug = dirname( $file );
		$slug = '.' === $slug ? basename( $file, '.php' ) : $slug;
		$ver  = '';
		$path = WP_PLUGIN_DIR . '/' . $file;
		if ( is_readable( $path ) && function_exists( 'get_file_data' ) ) {
			$d   = get_file_data( $path, array( 'v' => 'Version' ) );
			$ver = isset( $d['v'] ) ? (string) $d['v'] : '';
		}
		return array( 'slug' => sanitize_key( $slug ), 'version' => substr( preg_replace( '/[^0-9A-Za-z.\-+_]/', '', $ver ), 0, 30 ) );
	}

	public static function on_plugin_activated( $file ) {
		if ( plugin_basename( EMPEDIA_CLOUD_FILE ) === $file ) {
			return;
		}
		self::record( 'plugin_activated', self::plugin_detail( $file ) );
	}

	public static function on_plugin_deactivated( $file ) {
		if ( plugin_basename( EMPEDIA_CLOUD_FILE ) === $file ) {
			return;
		}
		self::record( 'plugin_deactivated', self::plugin_detail( $file ) );
	}

	public static function on_plugin_deleted( $file, $deleted ) {
		if ( $deleted ) {
			$slug = dirname( $file );
			self::record( 'plugin_deleted', array( 'slug' => sanitize_key( '.' === $slug ? basename( $file, '.php' ) : $slug ), 'version' => '' ) );
		}
	}

	public static function on_theme( $name ) {
		$t = wp_get_theme();
		self::record( 'theme_switched', array( 'slug' => sanitize_key( $t->get_stylesheet() ), 'version' => substr( preg_replace( '/[^0-9A-Za-z.\-+_]/', '', (string) $t->get( 'Version' ) ), 0, 30 ) ) );
	}

	public static function on_upgrade( $upgrader, $extra ) {
		if ( ! is_array( $extra ) || empty( $extra['type'] ) || empty( $extra['action'] ) ) {
			return;
		}
		if ( 'plugin' === $extra['type'] && in_array( $extra['action'], array( 'install', 'update' ), true ) ) {
			$files = array();
			if ( ! empty( $extra['plugins'] ) ) {
				$files = (array) $extra['plugins'];
			} elseif ( ! empty( $extra['plugin'] ) ) {
				$files = array( $extra['plugin'] );
			} elseif ( 'install' === $extra['action'] && is_object( $upgrader ) && method_exists( $upgrader, 'plugin_info' ) && $upgrader->plugin_info() ) {
				$files = array( $upgrader->plugin_info() );
			}
			foreach ( array_slice( $files, 0, 10 ) as $f ) {
				if ( is_string( $f ) && plugin_basename( EMPEDIA_CLOUD_FILE ) !== $f ) {
					self::record( 'install' === $extra['action'] ? 'plugin_installed' : 'plugin_updated', self::plugin_detail( $f ) );
				}
			}
		}
		if ( 'theme' === $extra['type'] && in_array( $extra['action'], array( 'install', 'update' ), true ) ) {
			$themes = ! empty( $extra['themes'] ) ? (array) $extra['themes'] : ( ! empty( $extra['theme'] ) ? array( $extra['theme'] ) : array() );
			foreach ( array_slice( $themes, 0, 10 ) as $slug ) {
				if ( is_string( $slug ) ) {
					$t = wp_get_theme( $slug );
					self::record( 'install' === $extra['action'] ? 'theme_installed' : 'theme_updated', array( 'slug' => sanitize_key( $slug ), 'version' => substr( preg_replace( '/[^0-9A-Za-z.\-+_]/', '', (string) $t->get( 'Version' ) ), 0, 30 ) ) );
				}
			}
		}
	}

	public static function on_core_updated( $version ) {
		self::record( 'core_updated', array( 'slug' => 'wordpress', 'version' => substr( preg_replace( '/[^0-9A-Za-z.\-+_]/', '', (string) $version ), 0, 30 ) ) );
	}

	public static function on_backup() {
		update_option( 'empedia_cloud_last_backup', time(), false );
		// An upload to a storage target that failed counts as a failed backup ( the local copy exists, the cloud tells them apart ).
		$st = class_exists( 'Empedia_Cloud_Backup' ) ? Empedia_Cloud_Backup::state() : null;
		self::record( $st && ! empty( $st['remote_error'] ) ? 'backup_failed' : 'backup_done', array() );
	}

	public static function on_backup_failed() {
		self::record( 'backup_failed', array() );
	}

	public static function on_restore() {
		self::record( 'restore_done', array() );
	}
}
