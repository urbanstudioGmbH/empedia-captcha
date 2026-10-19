<?php
/**
 * Backups: files + database in small steps ( WP-Cron / admin polling ), stored on this server, optional encryption,
 * restore with a safety dump first. Remote targets are added on top of this ( see Empedia_Cloud_Backup_Target ).
 *
 * Working rules:
 * - every step is resumable and limited by time ( no PHP time-limit problems on shared hosting ),
 * - the backup folder lies in wp-content under a secret name and is closed for web access,
 * - restoring never overwrites wp-config.php or this plugin, the restore state lives in a file ( the options table is replaced ).
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions -- backup archives are streamed in small chunks; WP_Filesystem cannot read or write partially.

class Empedia_Cloud_Backup {

	const SETTINGS  = 'empedia_backup_settings';
	const INDEX     = 'empedia_backup_index';
	const KEY       = 'empedia_backup_key';
	const STATE     = 'empedia_backup_state';
	const HOOK_TICK = 'empedia_cloud_backup_tick';
	const HOOK_AUTO = 'empedia_cloud_backup_auto';
	const LOCK      = 'backup_lock';
	const BUDGET    = 8;                 // seconds of work per step
	const ZIP_BYTES = 25 * 1048576;      // data added to the archive per step
	const CHUNK     = 1048576;           // encryption block
	const MAGIC     = 'EMPBK1';

	/* ---------------------------------------------------------------- settings */

	public static function defaults() {
		return array(
			'scope'    => 'both',   // both | files | db
			'schedule' => 'off',    // off | daily | weekly
			'keep'     => 3,
			'encrypt'  => false,
			'exclude'  => '', // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- own settings key, not a WP_Query argument.
			'remote'   => false,  // also upload to the EMPEDIAcloud storage
			'keep_remote' => 5,
		);
	}

	public static function settings() {
		$s = get_option( self::SETTINGS, array() );
		$s = wp_parse_args( is_array( $s ) ? $s : array(), self::defaults() );
		$s['scope']    = in_array( $s['scope'], array( 'both', 'files', 'db' ), true ) ? $s['scope'] : 'both';
		$s['schedule'] = in_array( $s['schedule'], array( 'off', 'daily', 'weekly' ), true ) ? $s['schedule'] : 'off';
		$s['keep']     = max( 1, min( 30, (int) $s['keep'] ) );
		$s['encrypt']  = ! empty( $s['encrypt'] );
		$s['exclude']  = (string) $s['exclude']; // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- own settings key, not a WP_Query argument.
		$s['remote']   = ! empty( $s['remote'] );
		$s['keep_remote'] = max( 1, min( 60, (int) $s['keep_remote'] ) );
		return $s;
	}

	public static function save_settings( array $in ) {
		$d = self::defaults();
		update_option(
			self::SETTINGS,
			array(
				'scope'    => isset( $in['scope'] ) ? sanitize_key( $in['scope'] ) : $d['scope'],
				'schedule' => isset( $in['schedule'] ) ? sanitize_key( $in['schedule'] ) : $d['schedule'],
				'keep'     => isset( $in['keep'] ) ? (int) $in['keep'] : $d['keep'],
				'encrypt'  => ! empty( $in['encrypt'] ),
				'remote'   => ! empty( $in['remote'] ),
				'keep_remote' => isset( $in['keep_remote'] ) ? (int) $in['keep_remote'] : $d['keep_remote'],
				'exclude'  => isset( $in['exclude'] ) ? substr( implode( "\n", array_filter( array_map( array( __CLASS__, 'clean_rel' ), preg_split( '/\R/', (string) $in['exclude'] ) ) ) ), 0, 4000 ) : '', // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- own settings key, not a WP_Query argument.
			),
			false
		);
		self::ensure_schedule();
	}

	private static function clean_rel( $p ) {
		$p = trim( str_replace( '\\', '/', (string) $p ), " \t/" );
		return preg_match( '#(^|/)\.\.(/|$)#', $p ) ? '' : $p;
	}

	/* ------------------------------------------------------------------ hooks */

	public static function init() {
		add_action( self::HOOK_TICK, array( __CLASS__, 'tick' ) );
		add_action( self::HOOK_AUTO, array( __CLASS__, 'auto' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
	}

	public static function ensure_schedule() {
		$s = self::settings();
		if ( self::running() && ! wp_next_scheduled( self::HOOK_TICK ) && ! Empedia_Cloud_Atomic::locked( self::LOCK ) ) {
			wp_schedule_single_event( time() + 10, self::HOOK_TICK );
		}
		$next = wp_next_scheduled( self::HOOK_AUTO );
		if ( 'off' !== $s['schedule'] && ! $next ) {
			wp_schedule_event( time() + wp_rand( 1800, 10800 ), 'daily', self::HOOK_AUTO );
		} elseif ( 'off' === $s['schedule'] && $next ) {
			wp_clear_scheduled_hook( self::HOOK_AUTO );
		}
	}

	public static function unschedule() {
		wp_clear_scheduled_hook( self::HOOK_AUTO );
		wp_clear_scheduled_hook( self::HOOK_TICK );
	}

	/** Daily event: weekly means “on Sundays” ( site time ). */
	public static function auto() {
		$s = self::settings();
		if ( 'off' === $s['schedule'] || ( 'weekly' === $s['schedule'] && 0 !== (int) wp_date( 'w' ) ) ) {
			return;
		}
		self::start( false );
	}

	/* ---------------------------------------------------------------- storage */

	/** Folder for backups ( created on demand, closed for web access ). */
	public static function dir() {
		$name = 'empedia-backups-' . substr( hash_hmac( 'sha256', 'empedia-backup-dir', wp_salt( 'auth' ) ), 0, 12 );
		$dir  = WP_CONTENT_DIR . '/' . $name;
		if ( ! is_dir( $dir ) ) {
			wp_mkdir_p( $dir );
		}
		if ( is_dir( $dir ) ) {
			if ( ! file_exists( $dir . '/index.php' ) ) {
				// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- the folder is in wp-content (not the plugin folder) and survives plugin updates.
				file_put_contents( $dir . '/index.php', "<?php // Silence is golden.\n" );
			}
			if ( ! file_exists( $dir . '/.htaccess' ) ) {
				// phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- see above.
				file_put_contents( $dir . '/.htaccess', "# EMPEDIAcloud: no web access\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n" );
			}
		}
		return $dir;
	}

	public static function index() {
		$i = get_option( self::INDEX, array() );
		return is_array( $i ) ? array_values( $i ) : array();
	}

	private static function save_index( array $i ) {
		update_option( self::INDEX, array_values( $i ), false );
		file_put_contents( self::dir() . '/index.json', wp_json_encode( array_values( $i ) ) ); // survives a restore of the database
	}

	/** Index from the mirror file ( after a restore the options table holds an older state ). */
	public static function rebuild_index() {
		$f = self::dir() . '/index.json';
		$j = is_file( $f ) ? json_decode( (string) file_get_contents( $f ), true ) : null;
		if ( is_array( $j ) ) {
			update_option( self::INDEX, array_values( $j ), false );
		}
	}

	public static function find( $id ) {
		foreach ( self::index() as $e ) {
			if ( isset( $e['id'] ) && $e['id'] === $id ) {
				return $e;
			}
		}
		return null;
	}

	public static function path_of( array $e ) {
		return self::dir() . '/' . basename( $e['file'] );
	}

	public static function delete( $id ) {
		$out  = array();
		$done = false;
		foreach ( self::index() as $e ) {
			if ( $e['id'] === $id ) {
				$f = self::path_of( $e );
				if ( is_file( $f ) ) {
					wp_delete_file( $f );
				}
				$done = true;
				continue;
			}
			$out[] = $e;
		}
		self::save_index( $out );
		return $done;
	}

	/* ------------------------------------------------------------------ state */

	private static function work_dir( $id ) {
		return self::dir() . '/.work-' . preg_replace( '/[^A-Za-z0-9\-]/', '', $id );
	}

	public static function state() {
		$s = get_option( self::STATE, array() );
		return is_array( $s ) && ! empty( $s['phase'] ) ? $s : null;
	}

	public static function running() {
		$s = self::state();
		return $s && ! in_array( $s['phase'], array( 'done', 'failed' ), true ) && time() - (int) $s['started'] < 12 * HOUR_IN_SECONDS;
	}

	/** Starts a backup unless one is running ( or a restore ). @return bool */
	public static function start( $manual = true, array $over = array() ) {
		if ( self::running() || Empedia_Cloud_Restore::running() ) {
			return false;
		}
		$set = array_merge( self::settings(), $over );
		delete_option( 'empedia_backup_start_error' );
		$targets = array();
		if ( ! empty( $set['remote'] ) ) {
			if ( Empedia_Cloud_Client::is_connected() ) {
				Empedia_Cloud_Bunny::status( true ); // the cron run has no cached state
			}
			$targets = array_keys( Empedia_Cloud_Targets::active() );
		}
		$remote = (bool) $targets;
		if ( $remote ) {
			// Everything that leaves this server is encrypted here; with the EMPEDIAcloud storage the cloud also keeps the key.
			$set['encrypt'] = true;
			if ( in_array( 'cloud', $targets, true ) ) {
				$esc = Empedia_Cloud_Bunny::escrow_key();
				if ( is_wp_error( $esc ) ) {
					update_option( 'empedia_backup_start_error', $esc->get_error_message(), false );
					return false;
				}
			}
		}
		$id  = gmdate( 'Ymd-His' ) . '-' . strtolower( wp_generate_password( 6, false ) );
		$w   = self::work_dir( $id );
		if ( ! wp_mkdir_p( $w ) ) {
			return false;
		}
		$state = array(
			'id'      => $id,
			'started' => time(),
			'manual'  => (bool) $manual,
			'scope'   => $set['scope'],
			'encrypt' => (bool) $set['encrypt'],
			'remote'  => $remote,
			'targets' => $targets,
			'exclude' => (string) $set['exclude'], // phpcs:ignore WordPressVIPMinimum.Performance.WPQueryParams.PostNotIn_exclude -- own settings key, not a WP_Query argument.
			'phase'   => in_array( $set['scope'], array( 'both', 'db' ), true ) ? 'db' : 'list',
			'db'      => array( 'tables' => null, 'i' => 0, 'off' => 0, 'rows' => 0, 'bytes' => 0 ),
			'list'    => array( 'init' => false, 'files' => 0, 'bytes' => 0 ),
			'zip'     => array( 'pos' => 0, 'files' => 0, 'bytes' => 0 ),
			'enc'     => array( 'in' => 0, 'out' => 0, 'n' => 0 ),
			'up'      => array(),
		);
		update_option( self::STATE, $state, false );
		wp_clear_scheduled_hook( self::HOOK_TICK );
		wp_schedule_single_event( time() + 2, self::HOOK_TICK );
		if ( $manual && function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
		return true;
	}

	/** One step of work; reschedules itself until the backup is complete. */
	public static function tick() {
		$s = self::state();
		if ( ! $s || in_array( $s['phase'], array( 'done', 'failed' ), true ) ) {
			return;
		}
		if ( ! Empedia_Cloud_Atomic::claim( self::LOCK, 120 ) ) {
			return;
		}
		$t0 = microtime( true );
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}
		ignore_user_abort( true );
		try {
			$s = self::run( $s, $t0 );
		} catch ( Throwable $e ) {
			$s['phase'] = 'failed';
			$s['error'] = 'exception';
		}
		if ( 'done' === $s['phase'] || 'failed' === $s['phase'] ) {
			self::finalize( $s );
		} else {
			update_option( self::STATE, $s, false );
			wp_schedule_single_event( time() + ( $s['manual'] ? 3 : 15 ), self::HOOK_TICK );
		}
		Empedia_Cloud_Atomic::release( self::LOCK );
	}

	private static function out_of_time( $t0 ) {
		return ( microtime( true ) - $t0 ) >= self::BUDGET;
	}

	private static function run( array $s, $t0 ) {
		while ( ! self::out_of_time( $t0 ) && ! in_array( $s['phase'], array( 'done', 'failed' ), true ) ) {
			switch ( $s['phase'] ) {
				case 'db':
					if ( self::step_db( $s, $t0 ) ) {
						$s['phase'] = in_array( $s['scope'], array( 'both', 'files' ), true ) ? 'list' : 'pack';
					}
					break;
				case 'list':
					if ( self::step_list( $s, $t0 ) ) {
						$s['phase'] = 'zip';
					}
					break;
				case 'zip':
					if ( self::step_zip( $s, $t0 ) ) {
						$s['phase'] = 'pack';
					}
					break;
				case 'pack':
					self::step_pack( $s );
					$s['phase'] = $s['encrypt'] ? 'encrypt' : ( $s['remote'] ? 'upload' : 'done' );
					break;
				case 'encrypt':
					if ( self::step_encrypt( $s, $t0 ) ) {
						$s['phase'] = $s['remote'] ? 'upload' : 'done';
					}
					break;
				case 'upload':
					if ( self::step_upload( $s, $t0 ) ) {
						$s['phase'] = 'done';
					}
					break;
				default:
					$s['phase'] = 'failed';
					$s['error'] = 'phase';
			}
		}
		return $s;
	}

	/* ---------------------------------------------------------------- database */

	/** Tables of this installation; options/users last so a restore keeps working until the end. */
	public static function tables() {
		global $wpdb;
		$rows  = $wpdb->get_results( "SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'", ARRAY_N ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $q is a table name from SHOW TABLES, quoted with backticks.
		$names = array();
		foreach ( (array) $rows as $r ) {
			if ( 0 === strpos( $r[0], $wpdb->base_prefix ) ) {
				$names[] = $r[0];
			}
		}
		$late = array();
		foreach ( $names as $k => $n ) {
			if ( preg_match( '/(options|users|usermeta)$/', $n ) ) {
				$late[] = $n;
				unset( $names[ $k ] );
			}
		}
		usort(
			$late,
			static function ( $a, $b ) {
				$o = static function ( $n ) {
					return preg_match( '/usermeta$/', $n ) ? 1 : ( preg_match( '/users$/', $n ) ? 0 : 2 );
				};
				return $o( $a ) - $o( $b );
			}
		);
		return array_merge( array_values( $names ), $late );
	}

	private static function sql_value( $v, $numeric ) {
		global $wpdb;
		if ( null === $v ) {
			return 'NULL';
		}
		if ( $numeric && preg_match( '/^-?\d+(\.\d+)?([eE][-+]?\d+)?$/', (string) $v ) ) {
			return (string) $v;
		}
		$v = (string) $v;
		if ( $wpdb->dbh instanceof mysqli ) {
			return "'" . $wpdb->dbh->real_escape_string( $v ) . "'";
		}
		return "'" . $wpdb->remove_placeholder_escape( esc_sql( $v ) ) . "'";
	}

	/** Writes the dump into $file ( append, resumable through $st ). @return bool finished */
	public static function dump_step( array &$st, $file, $t0 ) {
		global $wpdb;
		$fh = fopen( $file, 'ab' );
		if ( ! $fh ) {
			throw new RuntimeException( 'write' );
		}
		if ( null === $st['tables'] ) {
			$st['tables'] = self::tables();
			fwrite( $fh, "-- EMPEDIAcloud backup\nSET NAMES utf8mb4;\nSET FOREIGN_KEY_CHECKS=0;\nSET SQL_MODE='NO_AUTO_VALUE_ON_ZERO';\n" );
		}
		while ( $st['i'] < count( $st['tables'] ) ) {
			$t = $st['tables'][ $st['i'] ];
			$q = '`' . str_replace( '`', '``', $t ) . '`';
			if ( 0 === $st['off'] ) {
				$create = $wpdb->get_row( "SHOW CREATE TABLE $q", ARRAY_N ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $q is a table name from SHOW TABLES, quoted with backticks.
				if ( ! $create || empty( $create[1] ) ) {
					throw new RuntimeException( 'create' );
				}
				fwrite( $fh, "DROP TABLE IF EXISTS $q;\n" . preg_replace( '/\s*\R\s*/', ' ', $create[1] ) . ";\n" );
			}
			$cols    = $wpdb->get_results( "SHOW COLUMNS FROM $q", ARRAY_A ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $q is a table name from SHOW TABLES, quoted with backticks.
			$num     = array();
			$names   = array();
			foreach ( (array) $cols as $c ) {
				$names[]           = '`' . str_replace( '`', '``', $c['Field'] ) . '`';
				$num[ $c['Field'] ] = (bool) preg_match( '/^(tiny|small|medium|big)?int|^decimal|^float|^double/i', $c['Type'] );
			}
			$keys  = $wpdb->get_results( "SHOW KEYS FROM $q WHERE Key_name = 'PRIMARY'", ARRAY_A ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $q is a table name from SHOW TABLES, quoted with backticks.
			$order = '';
			if ( $keys ) {
				$pk = array();
				foreach ( $keys as $k ) {
					$pk[] = '`' . str_replace( '`', '``', $k['Column_name'] ) . '`';
				}
				$order = ' ORDER BY ' . implode( ',', $pk );
			}
			$batch = 200;
			while ( true ) {
				$rows = $wpdb->get_results( "SELECT * FROM $q$order LIMIT $batch OFFSET " . (int) $st['off'], ARRAY_A ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- $q is a table name from SHOW TABLES, quoted with backticks.
				if ( ! $rows ) {
					break;
				}
				$vals = array();
				foreach ( $rows as $r ) {
					$one = array();
					foreach ( $r as $f => $v ) {
						$one[] = self::sql_value( $v, ! empty( $num[ $f ] ) );
					}
					$vals[] = '(' . implode( ',', $one ) . ')';
				}
				$sql = "INSERT INTO $q (" . implode( ',', $names ) . ') VALUES ' . implode( ',', $vals ) . ";\n";
				fwrite( $fh, $sql );
				$st['bytes'] += strlen( $sql );
				$st['rows']  += count( $rows );
				$st['off']   += count( $rows );
				if ( count( $rows ) < $batch ) {
					break;
				}
				if ( self::out_of_time( $t0 ) ) {
					fclose( $fh );
					return false;
				}
			}
			$st['i']++;
			$st['off'] = 0;
			if ( self::out_of_time( $t0 ) && $st['i'] < count( $st['tables'] ) ) {
				fclose( $fh );
				return false;
			}
		}
		fwrite( $fh, "SET FOREIGN_KEY_CHECKS=1;\n-- end\n" );
		fclose( $fh );
		return true;
	}

	private static function step_db( array &$s, $t0 ) {
		return self::dump_step( $s['db'], self::work_dir( $s['id'] ) . '/db.sql', $t0 );
	}

	/* ------------------------------------------------------------------- files */

	/** Paths ( relative to ABSPATH ) that are never part of a backup. */
	public static function excluded( $rel, $extra ) {
		static $base = null;
		if ( null === $base ) {
			$content = trim( str_replace( ABSPATH, '', trailingslashit( WP_CONTENT_DIR ) ), '/' );
			$base    = array(
				$content . '/' . basename( self::dir() ),
				$content . '/cache',
				$content . '/upgrade',
				$content . '/wflogs',
				'.git',
				'node_modules',
				'error_log',
			);
		}
		foreach ( $base as $b ) {
			if ( $rel === $b || 0 === strpos( $rel, $b . '/' ) || basename( $rel ) === $b ) {
				return true;
			}
		}
		foreach ( preg_split( '/\R/', (string) $extra ) as $x ) {
			$x = self::clean_rel( $x );
			if ( '' !== $x && ( $rel === $x || 0 === strpos( $rel, $x . '/' ) ) ) {
				return true;
			}
		}
		return false;
	}

	private static function step_list( array &$s, $t0 ) {
		$w     = self::work_dir( $s['id'] );
		$qfile = $w . '/dirs.json';
		$lfile = $w . '/files.lst';
		$root  = untrailingslashit( ABSPATH );
		if ( ! $s['list']['init'] ) {
			file_put_contents( $qfile, wp_json_encode( array( '' ) ) );
			$s['list']['init'] = true;
		}
		$queue = json_decode( (string) file_get_contents( $qfile ), true );
		$queue = is_array( $queue ) ? $queue : array();
		$out   = fopen( $lfile, 'ab' );
		if ( ! $out ) {
			throw new RuntimeException( 'write' );
		}
		while ( $queue && ! self::out_of_time( $t0 ) ) {
			$rel = array_pop( $queue );
			$abs = '' === $rel ? $root : $root . '/' . $rel;
			$ls  = @scandir( $abs ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! $ls ) {
				continue;
			}
			foreach ( $ls as $name ) {
				if ( '.' === $name || '..' === $name ) {
					continue;
				}
				$r = '' === $rel ? $name : $rel . '/' . $name;
				$a = $abs . '/' . $name;
				if ( is_link( $a ) || self::excluded( $r, $s['exclude'] ) ) {
					continue;
				}
				if ( is_dir( $a ) ) {
					$queue[] = $r;
				} elseif ( is_file( $a ) && is_readable( $a ) ) {
					$size = (int) filesize( $a );
					fwrite( $out, $size . "\t" . $r . "\n" );
					$s['list']['files']++;
					$s['list']['bytes'] += $size;
				}
			}
		}
		fclose( $out );
		file_put_contents( $qfile, wp_json_encode( $queue ) );
		return empty( $queue );
	}

	private static function step_zip( array &$s, $t0 ) {
		$w    = self::work_dir( $s['id'] );
		$lfh  = fopen( $w . '/files.lst', 'rb' );
		if ( ! $lfh ) {
			return true;
		}
		fseek( $lfh, (int) $s['zip']['pos'] );
		$zip = new ZipArchive();
		if ( true !== $zip->open( $w . '/files.zip', ZipArchive::CREATE ) ) {
			fclose( $lfh );
			throw new RuntimeException( 'zip' );
		}
		$added = 0;
		$bytes = 0;
		$root  = untrailingslashit( ABSPATH );
		$store = '/\.(jpe?g|png|gif|webp|avif|zip|gz|tgz|bz2|7z|rar|mp3|mp4|m4a|mov|webm|woff2?|pdf)$/i';
		$done  = false;
		while ( true ) {
			$line = fgets( $lfh );
			if ( false === $line ) {
				$done = true;
				break;
			}
			$p = strpos( $line, "\t" );
			if ( false === $p ) {
				continue;
			}
			$size = (int) substr( $line, 0, $p );
			$rel  = rtrim( substr( $line, $p + 1 ), "\r\n" );
			$abs  = $root . '/' . $rel;
			if ( is_file( $abs ) && is_readable( $abs ) ) {
				if ( $zip->addFile( $abs, $rel ) && preg_match( $store, $rel ) ) {
					$zip->setCompressionName( $rel, ZipArchive::CM_STORE );
				}
				$added++;
				$bytes += $size;
			}
			if ( $bytes >= self::ZIP_BYTES || self::out_of_time( $t0 ) || $added >= 4000 ) {
				break;
			}
		}
		$s['zip']['pos'] = ftell( $lfh );
		fclose( $lfh );
		if ( ! $zip->close() ) {
			throw new RuntimeException( 'zip' ); // a file vanished or the disk is full
		}
		$s['zip']['files'] += $added;
		$s['zip']['bytes'] += $bytes;
		return $done;
	}

	/* ---------------------------------------------------------------- finishing */

	private static function step_pack( array &$s ) {
		$w   = self::work_dir( $s['id'] );
		$zip = new ZipArchive();
		if ( true !== $zip->open( $w . '/files.zip', ZipArchive::CREATE ) ) {
			throw new RuntimeException( 'zip' );
		}
		if ( is_file( $w . '/db.sql' ) ) {
			$zip->addFile( $w . '/db.sql', 'db.sql' );
		}
		$manifest = array(
			'v'        => 1,
			'id'       => $s['id'],
			'created'  => gmdate( 'c' ),
			'scope'    => $s['scope'],
			'site_url' => site_url(),
			'home_url' => home_url(),
			'abspath'  => ABSPATH,
			'prefix'   => $GLOBALS['wpdb']->base_prefix,
			'wp'       => get_bloginfo( 'version' ),
			'php'      => PHP_VERSION,
			'plugin'   => EMPEDIA_CLOUD_VERSION,
			'multisite' => is_multisite(),
			'tables'   => is_array( $s['db']['tables'] ) ? count( $s['db']['tables'] ) : 0,
			'rows'     => (int) $s['db']['rows'],
			'files'    => (int) $s['zip']['files'],
			'bytes'    => (int) $s['zip']['bytes'],
		);
		$zip->addFromString( 'manifest.json', wp_json_encode( $manifest, JSON_PRETTY_PRINT ) );
		if ( ! $zip->close() ) {
			throw new RuntimeException( 'zip' );
		}
		$final = self::dir() . '/' . $s['id'] . '.zip';
		if ( ! rename( $w . '/files.zip', $final ) ) {
			throw new RuntimeException( 'move' );
		}
		$s['manifest'] = $manifest;
		$s['file']     = basename( $final );
	}

	/* -------------------------------------------------------------- encryption */

	/** Master key of this site ( created on first use ). @return string 32 bytes */
	public static function master_key() {
		$k = get_option( self::KEY, '' );
		$k = is_string( $k ) ? base64_decode( $k, true ) : false;
		if ( ! $k || 32 !== strlen( $k ) ) {
			$k = random_bytes( 32 );
			update_option( self::KEY, base64_encode( $k ), false );
		}
		return $k;
	}

	public static function set_master_key( $b64 ) {
		$k = base64_decode( (string) $b64, true );
		if ( ! $k || 32 !== strlen( $k ) ) {
			return false;
		}
		update_option( self::KEY, base64_encode( $k ), false );
		return true;
	}

	private static function sub_key( $id, $master, $sub8 ) {
		return sodium_crypto_generichash( $id . '|' . $sub8, $master, 32 );
	}

	/** Encrypts <id>.zip to <id>.zip.emp in blocks ( resumable ). @return bool finished */
	private static function step_encrypt( array &$s, $t0 ) {
		$in_path  = self::dir() . '/' . $s['id'] . '.zip';
		$out_path = $in_path . '.emp';
		$in       = fopen( $in_path, 'rb' );
		if ( ! $in ) {
			throw new RuntimeException( 'read' );
		}
		$size = filesize( $in_path );
		$out  = fopen( $out_path, $s['enc']['n'] ? 'ab' : 'wb' );
		if ( ! $out ) {
			throw new RuntimeException( 'write' );
		}
		if ( ! isset( $s['enc']['sub'] ) ) {
			$s['enc']['sub'] = bin2hex( random_bytes( 8 ) );
			fwrite( $out, self::MAGIC . hex2bin( $s['enc']['sub'] ) . pack( 'J', $size ) );
		}
		$key = self::sub_key( $s['id'], self::master_key(), hex2bin( $s['enc']['sub'] ) );
		fseek( $in, (int) $s['enc']['in'] );
		while ( $s['enc']['in'] < $size ) {
			$plain = fread( $in, self::CHUNK );
			$last  = ( $s['enc']['in'] + strlen( $plain ) ) >= $size;
			$nonce = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
			$ad    = pack( 'N', $s['enc']['n'] ) . ( $last ? 'L' : 'C' );
			$ct    = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( $plain, $ad, $nonce, $key );
			fwrite( $out, pack( 'N', strlen( $ct ) ) . $nonce . $ct );
			$s['enc']['in'] += strlen( $plain );
			$s['enc']['n']++;
			if ( self::out_of_time( $t0 ) && ! $last ) {
				fclose( $in );
				fclose( $out );
				return false;
			}
		}
		fclose( $in );
		fclose( $out );
		sodium_memzero( $key );
		wp_delete_file( $in_path );
		$s['file'] = basename( $out_path );
		return true;
	}

	/** Uploads the finished ( encrypted ) file in parts to every target; true when finished ( failures are recorded, the local backup stays ). */
	private static function step_upload( array &$s, $t0 ) {
		$file = self::dir() . '/' . $s['file'];
		if ( ! is_file( $file ) ) {
			$s['remote_error'] = 'read';
			return true;
		}
		if ( empty( $s['up'] ) ) {
			$s['up'] = array( 'ti' => 0, 'i' => 0, 'n' => 0, 'fail' => 0, 'size' => (int) filesize( $file ), 'sha' => hash_file( 'sha256', $file ) );
			$s['remote_ok']   = array();
			$s['remote_fail'] = array();
		}
		if ( function_exists( 'set_time_limit' ) ) {
			@set_time_limit( 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, Squiz.PHP.DiscouragedFunctions.Discouraged -- every backup step is a long-running slice; the limit is raised per slice.
		}
		$up = &$s['up'];
		while ( $up['ti'] < count( $s['targets'] ) ) {
			$tid = $s['targets'][ $up['ti'] ];
			$t   = Empedia_Cloud_Targets::get( $tid );
			if ( ! $t ) {
				$s['remote_fail'][] = $tid;
				self::next_target( $up );
				continue;
			}
			$ps = $t->part_size();
			$n  = max( 1, (int) ceil( $up['size'] / $ps ) );
			$r  = true;
			while ( $up['i'] < $n && true === $r ) {
				$i   = (int) $up['i'];
				$r   = $t->put_part( $s['id'] . '/' . Empedia_Cloud_Bunny::part_name( $s['file'], $i ), $file, $i * $ps, min( $ps, $up['size'] - $i * $ps ) );
				if ( true === $r ) {
					$up['i']++;
					if ( self::out_of_time( $t0 ) && $up['i'] < $n ) {
						return false;
					}
				}
			}
			if ( true === $r ) {
				$m = Empedia_Cloud_Targets::manifest( $s, $n, $ps );
				$r = $t->put( $s['id'] . '/manifest.json', wp_json_encode( $m ) );
			}
			if ( is_wp_error( $r ) ) {
				if ( ++$up['fail'] >= 6 ) {
					$s['remote_fail'][] = $tid;
					$t->remove( $s['id'] );
					$t->close();
					self::next_target( $up );
					continue;
				}
				sleep( 3 );
				return false;
			}
			$s['remote_ok'][] = $tid;
			Empedia_Cloud_Targets::prune( $t, self::settings()['keep_remote'] );
			$t->close();
			self::next_target( $up );
		}
		if ( $s['remote_fail'] ) {
			$s['remote_error'] = implode( ',', $s['remote_fail'] );
		}
		return true;
	}

	private static function next_target( array &$up ) {
		$up['ti']++;
		$up['i']    = 0;
		$up['fail'] = 0;
	}

	/**
	 * Decrypts an .emp file to $dest in blocks ( resumable through $st = array( 'off' => 0, 'n' => 0 ) ).
	 *
	 * @return bool|null true = finished, null = more to do, false = wrong key or damaged file.
	 */
	public static function decrypt_step( $src, $dest, $id, array &$st, $t0 ) {
		$in = fopen( $src, 'rb' );
		if ( ! $in ) {
			return false;
		}
		$npub = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
		$head = fread( $in, 22 );
		if ( 22 !== strlen( $head ) || self::MAGIC !== substr( $head, 0, 6 ) ) {
			fclose( $in );
			return false;
		}
		$total = unpack( 'J', substr( $head, 14, 8 ) )[1];
		$key   = self::sub_key( $id, self::master_key(), substr( $head, 6, 8 ) );
		$out   = fopen( $dest, empty( $st['off'] ) ? 'wb' : 'ab' );
		fseek( $in, empty( $st['off'] ) ? 22 : (int) $st['off'] );
		$st   += array( 'off' => 22, 'n' => 0, 'plain' => 0 );
		$st['off'] = max( 22, (int) $st['off'] );
		$result   = null;
		while ( null === $result ) {
			$len = fread( $in, 4 );
			if ( 4 !== strlen( (string) $len ) ) {
				$result = false;
				break;
			}
			$l  = unpack( 'N', $len )[1];
			$nn = fread( $in, $npub );
			$ct = $l > 16 && $l <= self::CHUNK + 64 ? fread( $in, $l ) : '';
			if ( strlen( $nn ) !== $npub || strlen( $ct ) !== $l ) {
				$result = false;
				break;
			}
			$last = false;
			$pt   = false;
			foreach ( array( 'C', 'L' ) as $flag ) {
				$pt = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $ct, pack( 'N', $st['n'] ) . $flag, $nn, $key );
				if ( false !== $pt ) {
					$last = 'L' === $flag;
					break;
				}
			}
			if ( false === $pt ) {
				$result = false;
				break;
			}
			fwrite( $out, $pt );
			$st['n']++;
			$st['plain'] += strlen( $pt );
			$st['off']    = ftell( $in );
			if ( $last ) {
				$result = $st['plain'] === $total; // a missing or extra block means a damaged file
			} elseif ( self::out_of_time( $t0 ) ) {
				break;
			}
		}
		fclose( $in );
		fclose( $out );
		sodium_memzero( $key );
		if ( false === $result ) {
			wp_delete_file( $dest );
		}
		return $result;
	}

	/* --------------------------------------------------------------- finalizing */

	private static function finalize( array $s ) {
		$w      = self::work_dir( $s['id'] );
		$failed = 'failed' === $s['phase'];
		if ( ! $failed ) {
			$file = self::dir() . '/' . $s['file'];
			$m    = isset( $s['manifest'] ) ? $s['manifest'] : array();
			$idx  = self::index();
			$idx[] = array(
				'id'        => $s['id'],
				'created'   => time(),
				'file'      => $s['file'],
				'size'      => is_file( $file ) ? (int) filesize( $file ) : 0,
				'sha256'    => is_file( $file ) ? hash_file( 'sha256', $file ) : '',
				'encrypted' => (bool) $s['encrypt'],
				'scope'     => $s['scope'],
				'files'     => isset( $m['files'] ) ? (int) $m['files'] : 0,
				'tables'    => isset( $m['tables'] ) ? (int) $m['tables'] : 0,
				'wp'        => isset( $m['wp'] ) ? $m['wp'] : '',
				'site_url'  => isset( $m['site_url'] ) ? $m['site_url'] : '',
				'manual'    => (bool) $s['manual'],
				'remote'    => isset( $s['remote_ok'] ) ? array_values( $s['remote_ok'] ) : array(),
			);
			usort(
				$idx,
				static function ( $a, $b ) {
					return $b['created'] - $a['created'];
				}
			);
			$keep = self::settings()['keep'];
			while ( count( $idx ) > $keep ) {
				$old = array_pop( $idx );
				$f   = self::path_of( $old );
				if ( is_file( $f ) ) {
					wp_delete_file( $f );
				}
			}
			self::save_index( $idx );
		}
		self::rrmdir( $w );
		update_option(
			self::STATE,
			array(
				'phase'    => $failed ? 'failed' : 'done',
				'id'       => $s['id'],
				'started'  => $s['started'],
				'finished' => time(),
				'error'    => $failed && isset( $s['error'] ) ? $s['error'] : '',
				'remote_error' => isset( $s['remote_error'] ) ? $s['remote_error'] : '',
				'remote_ok' => isset( $s['remote_ok'] ) ? $s['remote_ok'] : array(),
			),
			false
		);
		wp_clear_scheduled_hook( self::HOOK_TICK );
		if ( $failed ) {
			do_action( 'empedia_cloud_backup_failed', $s['id'] );
		} else {
			do_action( 'empedia_cloud_backup_done', $s['id'] );
		}
	}

	public static function rrmdir( $dir ) {
		if ( ! is_dir( $dir ) ) {
			return;
		}
		foreach ( (array) scandir( $dir ) as $f ) {
			if ( '.' === $f || '..' === $f ) {
				continue;
			}
			$p = $dir . '/' . $f;
			is_dir( $p ) && ! is_link( $p ) ? self::rrmdir( $p ) : @unlink( $p ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
		}
		@rmdir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
	}

	/** Progress for the admin screen. */
	public static function progress() {
		$s = self::state();
		$labels = array(
			'db'      => __( 'Saving the database …', 'empedia-shield' ),
			'list'    => __( 'Collecting files …', 'empedia-shield' ),
			'zip'     => __( 'Packing files …', 'empedia-shield' ),
			'pack'    => __( 'Finishing …', 'empedia-shield' ),
			'encrypt' => __( 'Encrypting …', 'empedia-shield' ),
			'upload'  => __( 'Uploading to the cloud storage …', 'empedia-shield' ),
		);
		$run = self::running();
		return array(
			'running' => $run,
			'label'   => $run && isset( $labels[ $s['phase'] ] ) ? $labels[ $s['phase'] ] : '',
			'failed'  => $s && 'failed' === $s['phase'],
		);
	}
}
