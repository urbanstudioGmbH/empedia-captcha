<?php
/**
 * Restore of a backup made by Empedia_Cloud_Backup ( same site address ): safety dump of the current database first,
 * then files, then the database. The state is kept in a file because the options table is replaced by the restore.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions -- backup archives are streamed in small chunks; WP_Filesystem cannot read or write partially.

class Empedia_Cloud_Restore {

	const HOOK_TICK = 'empedia_cloud_restore_tick';
	const LOCK      = 'restore_lock';
	const BUDGET    = 8;

	private static function file() {
		return Empedia_Cloud_Backup::dir() . '/.restore-state.json';
	}

	public static function state() {
		$f = self::file();
		$s = is_file( $f ) ? json_decode( (string) file_get_contents( $f ), true ) : null;
		return is_array( $s ) && ! empty( $s['phase'] ) ? $s : null;
	}

	private static function save( array $s ) {
		file_put_contents( self::file(), wp_json_encode( $s ) );
	}

	public static function running() {
		$s = self::state();
		return $s && ! in_array( $s['phase'], array( 'done', 'failed' ), true ) && time() - (int) $s['started'] < 6 * HOUR_IN_SECONDS;
	}

	public static function init() {
		add_action( self::HOOK_TICK, array( __CLASS__, 'tick' ) );
	}

	private static function work() {
		return Empedia_Cloud_Backup::dir() . '/.work-restore';
	}

	/** @return true|WP_Error */
	public static function start( $id, $target = '' ) {
		if ( Empedia_Cloud_Backup::running() || self::running() ) {
			return new WP_Error( 'busy', 'busy' );
		}
		$e      = Empedia_Cloud_Backup::find( $id );
		$remote = false;
		if ( ! $e || ! is_file( Empedia_Cloud_Backup::path_of( $e ) ) ) {
			// Not on this server any more: take it from a storage target.
			$e   = null;
			$use = $target ? array( $target => Empedia_Cloud_Targets::get( $target ) ) : Empedia_Cloud_Targets::active();
			foreach ( $use as $tid => $t ) {
				$l = $t ? Empedia_Cloud_Targets::backups( $t, true ) : null;
				foreach ( is_array( $l ) ? $l : array() as $m ) {
					if ( $m['id'] === $id && ! $e ) {
						$e      = array( 'id' => $id, 'file' => $m['file'], 'encrypted' => true, 'scope' => $m['scope'], 'site_url' => $m['site_url'], 'parts' => (int) $m['parts'], 'size' => (int) $m['size'], 'sha256' => $m['sha256'] );
						$remote = (string) $tid;
					}
				}
			}
			if ( ! $e ) {
				return new WP_Error( 'missing', 'missing' );
			}
		}
		if ( ! in_array( $e['scope'], array( 'both', 'db', 'files' ), true ) ) {
			return new WP_Error( 'scope', 'scope' );
		}
		if ( untrailingslashit( $e['site_url'] ) !== untrailingslashit( site_url() ) ) {
			return new WP_Error( 'url_mismatch', 'url_mismatch' );
		}
		global $wpdb;
		// Own options ( connection, settings, key, backup list ) are put back after the import.
		$rows = $wpdb->get_results( "SELECT option_name, option_value, autoload FROM {$wpdb->options} WHERE option_name LIKE 'empedia\\_%'", ARRAY_A ); // phpcs:ignore WordPress.DB
		$keep = array();
		foreach ( (array) $rows as $r ) {
			if ( 0 === strpos( $r['option_name'], 'empedia_atm_' ) ) {
				continue; // locks and counters belong to the running site, not to the backup
			}
			$keep[] = array( $r['option_name'], base64_encode( $r['option_value'] ), $r['autoload'] );
		}
		wp_mkdir_p( self::work() );
		$s = array(
			'backup'  => $id,
			'file'    => $e['file'],
			'encrypted' => ! empty( $e['encrypted'] ),
			'scope'   => $e['scope'],
			'started' => time(),
			'phase'   => $remote ? 'fetch' : ( ! empty( $e['encrypted'] ) ? 'decrypt' : 'safety' ),
			'remote'  => (bool) $remote,
			'target'  => (string) $remote,
			'fetch'   => $remote ? array( 'i' => 0, 'n' => $e['parts'], 'size' => $e['size'], 'sha' => $e['sha256'] ) : array(),
			'dec'     => array( 'off' => 0, 'n' => 0, 'plain' => 0 ),
			'safety'  => array( 'tables' => null, 'i' => 0, 'off' => 0, 'rows' => 0, 'bytes' => 0 ),
			'files'   => array( 'i' => 0, 'done' => 0, 'skipped' => 0 ),
			'db'      => array( 'off' => 0, 'stmts' => 0, 'errors' => 0 ),
			'keep'    => $keep,
		);
		if ( 'db' === $e['scope'] ) {
			$s['files'] = array( 'i' => -1, 'done' => 0, 'skipped' => 0 );
		}
		self::save( $s );
		wp_clear_scheduled_hook( self::HOOK_TICK );
		wp_schedule_single_event( time() + 2, self::HOOK_TICK );
		return true;
	}

	private static function out_of_time( $t0 ) {
		return ( microtime( true ) - $t0 ) >= self::BUDGET;
	}

	private static function archive( array $s ) {
		return $s['encrypted'] ? self::work() . '/backup.zip' : Empedia_Cloud_Backup::dir() . '/' . basename( $s['file'] );
	}

	public static function tick() {
		$s = self::state();
		if ( ! $s || in_array( $s['phase'], array( 'done', 'failed' ), true ) ) {
			return;
		}
		if ( ! Empedia_Cloud_Atomic::claim( self::LOCK, 120 ) ) {
			return;
		}
		ignore_user_abort( true );
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}
		$t0 = microtime( true );
		try {
			while ( ! self::out_of_time( $t0 ) && ! in_array( $s['phase'], array( 'done', 'failed' ), true ) ) {
				self::step( $s, $t0 );
				self::save( $s );
			}
		} catch ( Throwable $e ) {
			$s['phase'] = 'failed';
			$s['error'] = 'exception';
		}
		if ( in_array( $s['phase'], array( 'done', 'failed' ), true ) ) {
			self::finish( $s );
		} else {
			self::save( $s );
			wp_schedule_single_event( time() + 3, self::HOOK_TICK );
		}
		Empedia_Cloud_Atomic::release( self::LOCK );
	}

	private static function step( array &$s, $t0 ) {
		switch ( $s['phase'] ) {
			case 'fetch':
				$dest = Empedia_Cloud_Backup::dir() . '/' . basename( $s['file'] );
				if ( 0 === (int) $s['fetch']['i'] && is_file( $dest ) ) {
					wp_delete_file( $dest );
				}
				while ( $s['fetch']['i'] < $s['fetch']['n'] && ! self::out_of_time( $t0 ) ) {
					$t = Empedia_Cloud_Targets::get( $s['target'] );
				$r = $t ? $t->get_to( $s['backup'] . '/' . Empedia_Cloud_Bunny::part_name( $s['file'], (int) $s['fetch']['i'] ), $dest ) : new WP_Error( 'target', 'target' );
					if ( is_wp_error( $r ) ) {
						$s['fetch']['fail'] = isset( $s['fetch']['fail'] ) ? $s['fetch']['fail'] + 1 : 1;
						if ( $s['fetch']['fail'] >= 6 ) {
							$s['phase'] = 'failed';
							$s['error'] = 'fetch';
							return;
						}
						sleep( 3 );
						break;
					}
					$s['fetch']['i']++;
				}
				if ( $s['fetch']['i'] >= $s['fetch']['n'] ) {
					if ( ! is_file( $dest ) || hash_file( 'sha256', $dest ) !== $s['fetch']['sha'] ) {
						$s['phase'] = 'failed';
						$s['error'] = 'fetch';
					} else {
						$s['phase'] = 'decrypt';
					}
				}
				break;
			case 'decrypt':
				$e = Empedia_Cloud_Backup::find( $s['backup'] );
				$r = Empedia_Cloud_Backup::decrypt_step( Empedia_Cloud_Backup::dir() . '/' . basename( $s['file'] ), self::archive( $s ), $s['backup'], $s['dec'], $t0 );
				unset( $e );
				if ( false === $r ) {
					$s['phase'] = 'failed';
					$s['error'] = 'decrypt'; // wrong key or damaged file
				} elseif ( true === $r ) {
					$s['phase'] = 'safety';
				}
				break;
			case 'safety':
				if ( Empedia_Cloud_Backup::dump_step( $s['safety'], Empedia_Cloud_Backup::dir() . '/safety-' . gmdate( 'Ymd-His', (int) $s['started'] ) . '.sql', $t0 ) ) {
					self::prune_safety();
					$s['phase'] = 'files';
				}
				break;
			case 'files':
				if ( self::step_files( $s, $t0 ) ) {
					$s['phase'] = 'db';
				}
				break;
			case 'db':
				if ( self::step_db( $s, $t0 ) ) {
					$s['phase'] = 'done';
				}
				break;
			default:
				$s['phase'] = 'failed';
				$s['error'] = 'phase';
		}
	}

	private static function prune_safety() {
		$files = glob( Empedia_Cloud_Backup::dir() . '/safety-*.sql' );
		if ( $files && count( $files ) > 2 ) {
			sort( $files );
			foreach ( array_slice( $files, 0, count( $files ) - 2 ) as $f ) {
				wp_delete_file( $f );
			}
		}
	}

	/** Never overwritten by a restore. */
	private static function protected_path( $name ) {
		$content = trim( str_replace( ABSPATH, '', trailingslashit( WP_CONTENT_DIR ) ), '/' );
		return 'wp-config.php' === $name
			|| 0 === strpos( $name, $content . '/plugins/' . dirname( plugin_basename( EMPEDIA_CLOUD_FILE ) ) . '/' )
			|| 0 === strpos( $name, $content . '/plugins/empedia-cloud/' )
			|| 0 === strpos( $name, $content . '/' . basename( Empedia_Cloud_Backup::dir() ) . '/' );
	}

	private static function step_files( array &$s, $t0 ) {
		if ( -1 === (int) $s['files']['i'] ) { // database-only backup
			return self::extract_sql( $s );
		}
		$zip = new ZipArchive();
		if ( true !== $zip->open( self::archive( $s ) ) ) {
			throw new RuntimeException( 'zip' );
		}
		$n    = $zip->numFiles;
		$root = untrailingslashit( ABSPATH );
		while ( $s['files']['i'] < $n ) {
			$name = $zip->getNameIndex( $s['files']['i'] );
			$s['files']['i']++;
			if ( false === $name || '/' === substr( $name, -1 ) || 'manifest.json' === $name || 'db.sql' === $name ) {
				continue;
			}
			if ( '' === $name || '/' === $name[0] || false !== strpos( $name, '..' ) || false !== strpos( $name, '\\' ) || false !== strpos( $name, "\0" ) || self::protected_path( $name ) ) {
				$s['files']['skipped']++;
				continue;
			}
			$target = $root . '/' . $name;
			wp_mkdir_p( dirname( $target ) );
			$in = $zip->getStream( $name );
			if ( ! $in ) {
				$s['files']['skipped']++;
				continue;
			}
			$out = @fopen( $target, 'wb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
			if ( ! $out ) {
				fclose( $in );
				$s['files']['skipped']++;
				continue;
			}
			stream_copy_to_stream( $in, $out );
			fclose( $in );
			fclose( $out );
			$s['files']['done']++;
			if ( self::out_of_time( $t0 ) ) {
				$zip->close();
				return false;
			}
		}
		$zip->close();
		return self::extract_sql( $s );
	}

	private static function extract_sql( array $s ) {
		$zip = new ZipArchive();
		if ( true !== $zip->open( self::archive( $s ) ) ) {
			throw new RuntimeException( 'zip' );
		}
		$ok = true;
		if ( false !== $zip->locateName( 'db.sql' ) ) {
			$in  = $zip->getStream( 'db.sql' );
			$out = fopen( self::work() . '/db.sql', 'wb' );
			if ( $in && $out ) {
				stream_copy_to_stream( $in, $out );
			} else {
				$ok = false;
			}
			if ( $in ) {
				fclose( $in );
			}
			if ( $out ) {
				fclose( $out );
			}
		}
		$zip->close();
		if ( ! $ok ) {
			throw new RuntimeException( 'sql' );
		}
		return true;
	}

	private static function step_db( array &$s, $t0 ) {
		global $wpdb;
		$f = self::work() . '/db.sql';
		if ( ! is_file( $f ) ) {
			return true; // files-only backup
		}
		$fh = fopen( $f, 'rb' );
		fseek( $fh, (int) $s['db']['off'] );
		$wpdb->suppress_errors( true );
		$done = true;
		while ( false !== ( $line = fgets( $fh ) ) ) {
			$line = rtrim( $line, "\r\n" );
			if ( '' !== $line && 0 !== strpos( $line, '--' ) ) {
				$r = $wpdb->query( $line ); // phpcs:ignore WordPress.DB, PluginCheck.Security.DirectDB.UnescapedDBParameter -- one statement of the site's own backup file (restoring is the purpose).
				$s['db']['stmts']++;
				if ( false === $r ) {
					$s['db']['errors']++;
				}
			}
			$s['db']['off'] = ftell( $fh );
			if ( self::out_of_time( $t0 ) ) {
				$done = false;
				break;
			}
		}
		fclose( $fh );
		return $done;
	}

	private static function finish( array $s ) {
		global $wpdb;
		$failed = 'failed' === $s['phase'];
		if ( ! $failed && is_file( self::work() . '/db.sql' ) ) {
			// Locks and counters inside the dump describe the moment of the backup, not now.
			$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'empedia\\_atm\\_%'" ); // phpcs:ignore WordPress.DB
			// Own options back ( connection, settings, key, backup list ).
			foreach ( isset( $s['keep'] ) ? $s['keep'] : array() as $r ) {
				$wpdb->replace( $wpdb->options, array( 'option_name' => $r[0], 'option_value' => base64_decode( $r[1] ), 'autoload' => $r[2] ), array( '%s', '%s', '%s' ) ); // phpcs:ignore WordPress.DB
			}
			wp_cache_flush();
		}
		Empedia_Cloud_Backup::rebuild_index();
		Empedia_Cloud_Backup::rrmdir( self::work() );
		if ( ! empty( $s['remote'] ) && ! empty( $s['file'] ) ) {
			wp_delete_file( Empedia_Cloud_Backup::dir() . '/' . basename( $s['file'] ) ); // the copy fetched from the cloud
		}
		$s['finished'] = time();
		unset( $s['keep'] );
		self::save( $s );
		wp_clear_scheduled_hook( self::HOOK_TICK );
		if ( $failed ) {
			do_action( 'empedia_cloud_restore_failed', $s['backup'] );
		} else {
			do_action( 'empedia_cloud_restore_done', $s['backup'] );
		}
	}

	public static function progress() {
		$s      = self::state();
		$labels = array(
			'fetch'   => __( 'Downloading from the cloud storage …', 'empedia-shield' ),
			'decrypt' => __( 'Decrypting …', 'empedia-shield' ),
			'safety'  => __( 'Saving the current database as a safety copy …', 'empedia-shield' ),
			'files'   => __( 'Restoring files …', 'empedia-shield' ),
			'db'      => __( 'Restoring the database …', 'empedia-shield' ),
		);
		$run = self::running();
		return array(
			'running' => $run,
			'label'   => $run && isset( $labels[ $s['phase'] ] ) ? $labels[ $s['phase'] ] : '',
			'failed'  => $s && 'failed' === $s['phase'],
			'done'    => $s && 'done' === $s['phase'],
		);
	}
}
