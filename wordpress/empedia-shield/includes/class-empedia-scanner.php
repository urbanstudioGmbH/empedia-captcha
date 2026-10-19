<?php
/**
 * File integrity scanner, runs in small steps ( WP-Cron ) and never sends file contents anywhere.
 *
 *  - WordPress core: every file is compared with the official checksums of wordpress.org ( changed, missing, foreign files ).
 *  - Plugins from wordpress.org: the same with the official checksums of the installed version.
 *  - PHP files in the uploads folder.
 *  - Code that has no official checksums ( premium plugins, themes, mu-plugins ) and every file found above is searched for
 *    well-known backdoor patterns. These are hints to check, never a statement that the site is infected.
 *
 * Only paths and rule codes are stored and reported. Files the owner marked as expected are left out.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Scanner {

	const STATE      = 'empedia_cloud_scan_state';
	const RESULT     = 'empedia_cloud_scan_result';
	const IGNORE     = 'empedia_cloud_scan_ignore';
	const SETTINGS   = 'empedia_cloud_scanner';
	const HOOK_TICK  = 'empedia_cloud_scan_tick';
	const HOOK_DAILY = 'empedia_cloud_scan_daily';
	const LOCK       = 'scan_lock'; // key of the atomic lock ( Empedia_Cloud_Atomic )
	const BUDGET     = 6.0;      // seconds of work per step
	const MAX_FILE   = 524288;   // chunk size for the pattern search
	const MAX_FILE_TOTAL = 2097152; // largest file that is searched for patterns
	const MAX_SIG    = 4000;     // files searched per scan
	const MAX_WALK   = 60000;    // files looked at per walk
	const CAP        = 25;       // entries per list in the result

	/** Code of the rules → reported to the cloud, texts are rendered there ( wpi.sig.<code> ). */
	public static function signatures() {
		return array(
			'eval_base64'    => '/eval\s*\(\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|convert_uudecode|hex2bin|strrev|urldecode|rawurldecode)?\s*\(?\s*base64_decode\s*\(/i',
			'eval_decode'    => '/eval\s*\(\s*(?:gzdecode|convert_uudecode|hex2bin|strrev|urldecode|rawurldecode|str_rot13)\s*\(/i',
			'eval_input'     => '/eval\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/',
			'assert_input'   => '/assert\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/',
			'shell_input'    => '/(?<![\w>:$])@?(?:system|passthru|shell_exec|exec|popen|proc_open)\s*\(\s*(?:base64_decode\s*\(|[^;]{0,80}?\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b)/',
			'webshell_name'  => '/FilesMan|r57shell|c99shell|b374k/',
			'include_input'  => '/\binclude(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b|\brequire(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/',
			'input_function' => '/\$_(?:COOKIE|REQUEST|POST|GET)\s*\[\s*[\'"][^\'"]{1,40}[\'"]\s*\]\s*\(\s*\$_(?:COOKIE|REQUEST|POST|GET)/',
			'variable_call'  => '/\$\w+\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/',
			'callback_exec'  => '/\b(?:array_map|array_filter|array_walk|usort|uasort|uksort|ob_start|register_shutdown_function)\s*\(\s*[\'"](?:assert|system|exec|passthru|shell_exec|eval)[\'"]/',
			'globals_call'   => '/\$GLOBALS\s*\[\s*[\'"][^\'"]{1,40}[\'"]\s*\]\s*\(/',
			'phpinput_eval'  => '/php:\/\/input[\s\S]{0,200}?\beval\b|\beval\b[\s\S]{0,200}?php:\/\/input/',
			'upload_php'     => '/(?:move_uploaded_file|copy)\s*\([^)]*\$_FILES[^)]*\.\s*[\'"]?\.?(?:php|phtml|phar)/i',
			'rogue_admin'    => '/wp_(?:insert|create)_user\s*\([^;]{0,300}?[\'"]administrator[\'"]/',
			'preg_e_input'   => '/preg_replace\s*\(\s*[\'"][^\'"\n]*\/[imsuxADSUXJ]*e[imsuxADSUXJ]*[\'"]\s*,[^;]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)/',
		);
	}

	public static function htaccess_signatures() {
		return array(
			'htaccess_prepend' => '/^\s*(?:php_value\s+)?(?:auto_prepend_file|auto_append_file)\b.+$/im',
			'htaccess_handler' => '/^\s*AddHandler\s+[\w-]*php[\w.-]*\s+\.(?:jpe?g|png|gif|ico|txt|css|js)\b.*$/im',
		);
	}

	public static function init() {
		add_action( self::HOOK_TICK, array( __CLASS__, 'tick' ) );
		add_action( self::HOOK_DAILY, array( __CLASS__, 'daily' ) );
		add_action( 'init', array( __CLASS__, 'ensure_schedule' ) );
	}

	public static function settings() {
		$o = get_option( self::SETTINGS, array() );
		$o = is_array( $o ) ? $o : array();
		return array( 'auto' => ! isset( $o['auto'] ) || (bool) $o['auto'] );
	}

	public static function ensure_schedule() {
		// A step that died ( fatal error, time limit ) leaves a running state without a scheduled follow-up: pick it up again.
		if ( self::running() && ! wp_next_scheduled( self::HOOK_TICK ) && ! Empedia_Cloud_Atomic::locked( self::LOCK ) ) {
			wp_schedule_single_event( time() + 10, self::HOOK_TICK );
		}
		$auto = self::settings()['auto'];
		$next = wp_next_scheduled( self::HOOK_DAILY );
		if ( $auto && ! $next ) {
			wp_schedule_event( time() + wp_rand( 900, 7200 ), 'daily', self::HOOK_DAILY );
		} elseif ( ! $auto && $next ) {
			wp_clear_scheduled_hook( self::HOOK_DAILY );
		}
	}

	public static function clear_schedule() {
		wp_clear_scheduled_hook( self::HOOK_DAILY );
		wp_clear_scheduled_hook( self::HOOK_TICK );
	}

	public static function daily() {
		update_option( 'empedia_cloud_cron_seen', time(), false );
		Empedia_Cloud_Atomic::cleanup();
		self::start( false );
	}

	/* ------------------------------------------------------------------ state */

	public static function state() {
		$s = get_option( self::STATE, array() );
		return is_array( $s ) && ! empty( $s['phase'] ) ? $s : null;
	}

	public static function running() {
		$s = self::state();
		return $s && 'done' !== $s['phase'] && time() - (int) $s['started'] < 6 * HOUR_IN_SECONDS;
	}

	public static function result() {
		$r = get_option( self::RESULT, array() );
		return is_array( $r ) && ! empty( $r['finished'] ) ? $r : null;
	}

	/** Starts a scan unless one is running. @return bool */
	public static function start( $manual = true ) {
		if ( self::running() ) {
			return false;
		}
		$state = array(
			'id'        => wp_generate_password( 12, false ),
			'started'   => time(),
			'manual'    => (bool) $manual,
			'phase'     => 'core',
			'pos'       => 0,
			'postponed' => 0,
			'core'      => array( 'status' => 'pending', 'checked' => 0, 'modified' => array(), 'missing' => array(), 'extra' => array(), 'root_extra' => array() ),
			'plugins'   => array( 'checked' => 0, 'no_checksums' => array(), 'modified' => array(), 'extra' => array(), 'queue' => null, 'cur' => null ),
			'uploads'   => array( 'dirs' => null, 'files' => array(), 'visited' => 0 ),
			'sig'       => array( 'files' => array(), 'dirs' => null, 'scanned' => 0, 'hits' => array(), 'truncated' => false ),
		);
		update_option( self::STATE, $state, false );
		wp_clear_scheduled_hook( self::HOOK_TICK );
		wp_schedule_single_event( time() + 2, self::HOOK_TICK );
		if ( $manual && function_exists( 'spawn_cron' ) ) {
			spawn_cron();
		}
		return true;
	}

	/** One step of work; reschedules itself until the scan is complete. */
	public static function tick() {
		$s = self::state();
		if ( ! $s || 'done' === $s['phase'] ) {
			return;
		}
		if ( ! Empedia_Cloud_Atomic::claim( self::LOCK, 90 ) ) {
			return; // another step is running ( for example from the Files tab )
		}
		$t0 = microtime( true );
		// Not while the server is busy ( the scan is never urgent ).
		$load = function_exists( 'sys_getloadavg' ) ? sys_getloadavg() : false;
		if ( $load && $load[0] > (float) apply_filters( 'empedia_cloud_scan_max_load', 6.0 ) && $s['postponed'] < 6 ) {
			$s['postponed']++;
			update_option( self::STATE, $s, false );
			Empedia_Cloud_Atomic::release( self::LOCK );
			wp_schedule_single_event( time() + 300, self::HOOK_TICK );
			return;
		}
		if ( function_exists( 'wp_raise_memory_limit' ) ) {
			wp_raise_memory_limit( 'admin' );
		}
		try {
			$s = self::run( $s, $t0 );
		} catch ( Throwable $e ) {
			$s['phase'] = 'done';
			$s['error'] = 'exception';
		}
		if ( 'done' === $s['phase'] ) {
			self::finalize( $s );
		} else {
			update_option( self::STATE, $s, false );
			wp_schedule_single_event( time() + ( $s['manual'] ? 3 : 20 ), self::HOOK_TICK );
		}
		Empedia_Cloud_Atomic::release( self::LOCK );
	}

	private static function out_of_time( $t0 ) {
		return microtime( true ) - $t0 > self::BUDGET;
	}

	private static function run( $s, $t0 ) {
		while ( ! self::out_of_time( $t0 ) && 'done' !== $s['phase'] ) {
			switch ( $s['phase'] ) {
				case 'core':
					$s = self::step_core( $s, $t0 );
					break;
				case 'core_extra':
					$s = self::step_core_extra( $s, $t0 );
					break;
				case 'plugins':
					$s = self::step_plugins( $s, $t0 );
					break;
				case 'uploads':
					$s = self::step_uploads( $s, $t0 );
					break;
				case 'sig':
					$s = self::step_sig( $s, $t0 );
					break;
				default:
					$s['phase'] = 'done';
			}
		}
		return $s;
	}

	/* ------------------------------------------------------------------ helpers */

	/** Path as reported: relative to ABSPATH, or wp-content/… for a content folder outside it ( never an absolute path ). */
	private static function rel( $path ) {
		$p    = wp_normalize_path( $path );
		$root = trailingslashit( wp_normalize_path( ABSPATH ) );
		if ( 0 === strpos( $p, $root ) ) {
			return ltrim( substr( $p, strlen( $root ) ), '/' );
		}
		$c = trailingslashit( wp_normalize_path( WP_CONTENT_DIR ) );
		if ( 0 === strpos( $p, $c ) ) {
			return 'wp-content/' . ltrim( substr( $p, strlen( $c ) ), '/' );
		}
		return 'external/' . basename( $p );
	}

	private static function to_abs( $rel ) {
		return 0 === strpos( $rel, 'wp-content/' ) && ! file_exists( ABSPATH . $rel ) ? untrailingslashit( WP_CONTENT_DIR ) . '/' . substr( $rel, 11 ) : ABSPATH . $rel;
	}

	public static function is_php_ext( $name ) {
		return (bool) preg_match( '/\.(?:php[0-9]?|phtml|phar|pht|inc)$/i', $name );
	}

	/** A PHP file without any code ( “Silence is golden” ): nothing to report. */
	private static function is_empty_php( $path ) {
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > 400 ) {
			return false;
		}
		$c = @file_get_contents( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $c ) {
			return false;
		}
		$c = preg_replace( array( '#/\*.*?\*/#s', '#(?://|\#)[^\n]*#', '#<\?php#i', '#\?>#', '#\s+#' ), '', $c );
		return '' === $c;
	}

	private static function md5_ok( $file, $expected ) {
		$m = @md5_file( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $m ) {
			return true; // unreadable: no statement
		}
		foreach ( (array) $expected as $e ) {
			if ( is_string( $e ) && hash_equals( strtolower( $e ), $m ) ) {
				return true;
			}
		}
		return false;
	}

	private static function add_capped( &$list, $v ) {
		if ( count( $list ) < 500 ) {
			$list[] = $v;
		}
	}

	/** Lists a directory without following links; returns array( dirs, files ). */
	private static function list_dir( $dir ) {
		$dirs  = array();
		$files = array();
		$h     = @opendir( $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $h ) {
			return array( $dirs, $files );
		}
		while ( false !== ( $n = readdir( $h ) ) ) {
			if ( '.' === $n || '..' === $n ) {
				continue;
			}
			$p = $dir . '/' . $n;
			if ( is_link( $p ) ) {
				continue;
			}
			if ( is_dir( $p ) ) {
				$dirs[] = $p;
			} elseif ( is_file( $p ) ) {
				$files[] = $p;
			}
		}
		closedir( $h );
		sort( $dirs );
		sort( $files );
		return array( $dirs, $files );
	}

	/* ------------------------------------------------------------------ core */

	private static function core_map() {
		$m = get_option( 'empedia_cloud_scan_core', array() );
		return is_array( $m ) ? $m : array();
	}

	private static function step_core( $s, $t0 ) {
		if ( 'pending' === $s['core']['status'] ) {
			if ( ! function_exists( 'get_core_checksums' ) ) {
				require_once ABSPATH . 'wp-admin/includes/update.php';
			}
			global $wp_version, $wp_local_package;
			// The checksums follow the installed core package ( not the language chosen in the settings ).
			$loc  = ! empty( $wp_local_package ) ? $wp_local_package : 'en_US';
			$sums = get_core_checksums( $wp_version, $loc );
			if ( ! is_array( $sums ) && 'en_US' !== $loc ) {
				$sums = get_core_checksums( $wp_version, 'en_US' );
			}
			if ( ! is_array( $sums ) || ! $sums ) {
				$s['core']['status'] = 'unavailable';
				$s['phase']          = 'plugins';
				return $s;
			}
			update_option( 'empedia_cloud_scan_core', $sums, false );
			$s['core']['status'] = 'running';
			$s['core']['total']  = count( $sums );
			$s['pos']            = 0;
		}
		$sums = self::core_map();
		if ( ! $sums ) {
			$s['core']['status'] = 'unavailable';
			$s['phase']          = 'plugins';
			return $s;
		}
		$keys = array_keys( $sums );
		$n    = count( $keys );
		$skip = array( 'readme.html', 'license.txt', 'wp-config-sample.php', 'wp-content/plugins/index.php' );
		while ( $s['pos'] < $n && ! self::out_of_time( $t0 ) ) {
			$file = $keys[ $s['pos'] ];
			$s['pos']++;
			if ( 0 === strpos( $file, 'wp-content/' ) || in_array( $file, $skip, true ) ) {
				continue;
			}
			$path = ABSPATH . $file;
			if ( ! is_file( $path ) ) {
				if ( self::is_php_ext( $file ) ) {
					self::add_capped( $s['core']['missing'], $file );
				}
				continue;
			}
			$s['core']['checked']++;
			if ( ! self::md5_ok( $path, $sums[ $file ] ) ) {
				self::add_capped( $s['core']['modified'], $file );
				self::add_capped( $s['sig']['files'], $path );
			}
		}
		if ( $s['pos'] >= $n ) {
			$s['core']['status'] = 'ok';
			$s['phase']          = 'core_extra';
			$s['pos']            = 0;
			$s['walk']           = array( 'dirs' => array( untrailingslashit( ABSPATH . 'wp-admin' ), untrailingslashit( ABSPATH . 'wp-includes' ) ), 'root' => false, 'visited' => 0 );
		}
		return $s;
	}

	private static function step_core_extra( $s, $t0 ) {
		$sums = self::core_map();
		$w    = $s['walk'];
		if ( ! $sums ) {
			$s['phase'] = 'plugins';
			unset( $s['walk'] );
			return $s;
		}
		if ( empty( $w['root'] ) ) {
			list( , $files ) = self::list_dir( untrailingslashit( ABSPATH ) );
			foreach ( $files as $f ) {
				$name = basename( $f );
				if ( self::is_php_ext( $name ) && ! isset( $sums[ $name ] ) && ! preg_match( '/^(?:wp-config(?:-[\w.-]+)?|wordfence-waf)\.php$/i', $name ) && ! self::is_empty_php( $f ) ) {
					self::add_capped( $s['core']['root_extra'], $name );
					self::add_capped( $s['sig']['files'], $f );
				}
			}
			$w['root'] = true;
		}
		while ( $w['dirs'] && ! self::out_of_time( $t0 ) && $w['visited'] < self::MAX_WALK ) {
			$dir = array_pop( $w['dirs'] );
			list( $dirs, $files ) = self::list_dir( $dir );
			foreach ( $dirs as $d ) {
				$w['dirs'][] = $d;
			}
			foreach ( $files as $f ) {
				$w['visited']++;
				$name = basename( $f );
				$rel  = self::rel( $f );
				if ( self::is_php_ext( $name ) && ! isset( $sums[ $rel ] ) && 'error_log' !== $name && ! self::is_empty_php( $f ) ) {
					self::add_capped( $s['core']['extra'], $rel );
					self::add_capped( $s['sig']['files'], $f );
				}
			}
		}
		if ( ! $w['dirs'] || $w['visited'] >= self::MAX_WALK ) {
			unset( $s['walk'] );
			delete_option( 'empedia_cloud_scan_core' );
			$s['phase'] = 'plugins';
			$s['pos']   = 0;
		} else {
			$s['walk'] = $w;
		}
		return $s;
	}

	/* ------------------------------------------------------------------ plugins */

	private static function plugin_checksums( $slug, $version ) {
		$ck = 'empedia_cloud_scan_nock_' . md5( $slug . '|' . $version );
		if ( get_transient( $ck ) ) {
			return null;
		}
		$url = 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json';
		$res = wp_remote_get( $url, array( 'timeout' => 12 ) );
		if ( is_wp_error( $res ) ) {
			return false; // network problem: try again at the next scan, do not remember
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		$j    = 200 === $code ? json_decode( wp_remote_retrieve_body( $res ), true ) : null;
		if ( ! is_array( $j ) || empty( $j['files'] ) || ! is_array( $j['files'] ) ) {
			if ( 404 === $code || 200 === $code ) {
				set_transient( $ck, 1, 3 * DAY_IN_SECONDS ); // not hosted at wordpress.org
			}
			return null;
		}
		$map = array();
		foreach ( $j['files'] as $path => $h ) {
			$md5 = is_array( $h ) && isset( $h['md5'] ) ? (array) $h['md5'] : array();
			if ( $md5 && is_string( $path ) ) {
				$map[ $path ] = $md5;
			}
		}
		return $map;
	}

	private static function step_plugins( $s, $t0 ) {
		$p = $s['plugins'];
		if ( null === $p['queue'] ) {
			if ( ! function_exists( 'get_plugins' ) ) {
				require_once ABSPATH . 'wp-admin/includes/plugin.php';
			}
			$q = array();
			foreach ( get_plugins() as $file => $data ) {
				$dir = dirname( $file );
				if ( '.' === $dir ) {
					self::add_capped( $s['sig']['files'], WP_PLUGIN_DIR . '/' . $file ); // single-file plugin: no checksums possible
					continue;
				}
				$q[] = array( 'slug' => $dir, 'version' => (string) $data['Version'] );
			}
			$p['queue'] = $q;
			$p['cur']   = null;
		}
		while ( ! self::out_of_time( $t0 ) ) {
			if ( null === $p['cur'] ) {
				if ( ! $p['queue'] ) {
					break;
				}
				$item = array_shift( $p['queue'] );
				$map  = '' === $item['version'] ? null : self::plugin_checksums( $item['slug'], $item['version'] );
				if ( false === $map ) {
					$p['no_checksums'][] = $item['slug'];
					continue;
				}
				if ( null === $map ) {
					$p['no_checksums'][] = $item['slug'];
					$s['sig']['dirs']    = is_array( $s['sig']['dirs'] ) ? $s['sig']['dirs'] : array();
					$s['sig']['dirs'][]  = WP_PLUGIN_DIR . '/' . $item['slug'];
					continue;
				}
				update_option( 'empedia_cloud_scan_cur', $map, false );
				$p['cur'] = array( 'slug' => $item['slug'], 'stage' => 'verify', 'pos' => 0, 'dirs' => array( WP_PLUGIN_DIR . '/' . $item['slug'] ), 'visited' => 0 );
				$p['checked']++;
			}
			$map = get_option( 'empedia_cloud_scan_cur', false );
			if ( ! is_array( $map ) ) {
				$p['cur'] = null;
				continue;
			}
			$c    = $p['cur'];
			$slug = $c['slug'];
			if ( 'verify' === $c['stage'] ) {
				$keys = array_keys( $map );
				$n    = count( $keys );
				while ( $c['pos'] < $n && ! self::out_of_time( $t0 ) ) {
					$f = $keys[ $c['pos'] ];
					$c['pos']++;
					$path = WP_PLUGIN_DIR . '/' . $slug . '/' . $f;
					if ( is_file( $path ) && ! self::md5_ok( $path, $map[ $f ] ) ) {
						$p['modified'][ $slug ] = isset( $p['modified'][ $slug ] ) ? $p['modified'][ $slug ] : array();
						self::add_capped( $p['modified'][ $slug ], $f );
						self::add_capped( $s['sig']['files'], $path );
					}
				}
				if ( $c['pos'] >= $n ) {
					$c['stage'] = 'walk';
				}
			}
			if ( 'walk' === $c['stage'] && ! self::out_of_time( $t0 ) ) {
				$base = WP_PLUGIN_DIR . '/' . $slug . '/';
				while ( $c['dirs'] && ! self::out_of_time( $t0 ) && $c['visited'] < self::MAX_WALK ) {
					$dir = array_pop( $c['dirs'] );
					list( $dirs, $files ) = self::list_dir( $dir );
					foreach ( $dirs as $d ) {
						$c['dirs'][] = $d;
					}
					foreach ( $files as $f ) {
						$c['visited']++;
						$rel = ltrim( substr( wp_normalize_path( $f ), strlen( wp_normalize_path( $base ) ) ), '/' );
						if ( self::is_php_ext( $rel ) && ! isset( $map[ $rel ] ) && ! self::is_empty_php( $f ) ) {
							$p['extra'][ $slug ] = isset( $p['extra'][ $slug ] ) ? $p['extra'][ $slug ] : array();
							self::add_capped( $p['extra'][ $slug ], $rel );
							self::add_capped( $s['sig']['files'], $f );
						}
					}
				}
				if ( ! $c['dirs'] || $c['visited'] >= self::MAX_WALK ) {
					$p['cur'] = null;
					delete_option( 'empedia_cloud_scan_cur' );
					continue;
				}
			}
			$p['cur'] = $c;
		}
		$s['plugins'] = $p;
		if ( ! $p['queue'] && null === $p['cur'] ) {
			$s['phase'] = 'uploads';
			$u          = wp_get_upload_dir();
			$s['uploads']['dirs'] = ! empty( $u['basedir'] ) && is_dir( $u['basedir'] ) ? array( untrailingslashit( $u['basedir'] ) ) : array();
			// Code without official checksums: searched for patterns as well.
			$s['sig']['dirs'] = is_array( $s['sig']['dirs'] ) ? $s['sig']['dirs'] : array();
			foreach ( array( WPMU_PLUGIN_DIR, get_theme_root() ) as $d ) {
				if ( is_dir( $d ) ) {
					$s['sig']['dirs'][] = untrailingslashit( $d );
				}
			}
		}
		return $s;
	}

	/* ------------------------------------------------------------------ uploads */

	private static function step_uploads( $s, $t0 ) {
		$u = $s['uploads'];
		while ( $u['dirs'] && ! self::out_of_time( $t0 ) && $u['visited'] < self::MAX_WALK ) {
			$dir = array_pop( $u['dirs'] );
			list( $dirs, $files ) = self::list_dir( $dir );
			foreach ( $dirs as $d ) {
				$u['dirs'][] = $d;
			}
			foreach ( $files as $f ) {
				$u['visited']++;
				$name = basename( $f );
				if ( self::is_php_ext( $name ) && ! self::is_empty_php( $f ) ) {
					self::add_capped( $u['files'], self::rel( $f ) );
					self::add_capped( $s['sig']['files'], $f );
				} elseif ( '.htaccess' === $name || '.user.ini' === $name ) {
					self::add_capped( $s['sig']['files'], $f );
				}
			}
		}
		$s['uploads'] = $u;
		if ( ! $u['dirs'] || $u['visited'] >= self::MAX_WALK ) {
			$s['phase'] = 'sig';
		}
		return $s;
	}

	/* ------------------------------------------------------------------ patterns */

	/** Rule codes that match the content of one file. */
	public static function scan_content( $name, $content ) {
		$hits = array();
		if ( '.htaccess' === $name || '.user.ini' === $name ) {
			foreach ( self::htaccess_signatures() as $code => $re ) {
				if ( 1 === @preg_match( $re, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					$hits[] = $code;
				}
			}
			return $hits;
		}
		foreach ( self::signatures() as $code => $re ) {
			if ( 1 === @preg_match( $re, $content ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$hits[] = $code;
			}
		}
		return $hits;
	}

	private static function sig_file( $s, $path ) {
		// The two files that contain the pattern texts themselves ( their official checksums are not known to wordpress.org ).
		$own  = wp_normalize_path( (string) realpath( EMPEDIA_CLOUD_DIR . 'includes/' ) ) . '/';
		$real = realpath( $path );
		if ( false !== $real && in_array( wp_normalize_path( $real ), array( $own . 'class-empedia-scanner.php', $own . 'class-empedia-files-admin.php' ), true ) ) {
			return $s;
		}
		$name = basename( $path );
		$rel  = self::rel( $path );
		if ( preg_match( '#(?:^|/)(?:wp-vcd|wp-tmp|wp-feed|xmrlpc|c99\w*|r57\w*|b374k\w*|wso\d*|filesman|indoxploit|alfa-?shell|webshell|0byte)\.php\d?$#i', $rel ) ) {
			$s['sig']['hits'][ $rel ] = array( 'webshell_filename' );
			return $s;
		}
		if ( preg_match( '#(?:^|/)\.(?!php)[^/]+\.php\d?$#i', $rel ) ) {
			$s['sig']['hits'][ $rel ] = array( 'hidden_php' );
			return $s;
		}
		$size = @filesize( $path ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( false === $size || $size > self::MAX_FILE_TOTAL || ! $size ) {
			return $s;
		}
		// Large files are read in chunks ( a backdoor behind a lot of padding is still found ).
		$hits = array();
		$h    = @fopen( $path, 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		if ( ! $h ) {
			return $s;
		}
		$carry = '';
		while ( ! feof( $h ) ) {
			$chunk = fread( $h, self::MAX_FILE ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( false === $chunk || '' === $chunk ) {
				break;
			}
			$hits  = array_merge( $hits, self::scan_content( $name, $carry . $chunk ) );
			$carry = substr( $chunk, -512 );
		}
		fclose( $h ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$hits = array_values( array_unique( $hits ) );
		if ( $hits ) {
			$s['sig']['hits'][ $rel ] = $hits;
		}
		return $s;
	}

	private static function step_sig( $s, $t0 ) {
		$g = $s['sig'];
		// explicit files first
		while ( $g['files'] && ! self::out_of_time( $t0 ) && $g['scanned'] < self::MAX_SIG ) {
			$f = array_pop( $g['files'] );
			if ( ! is_file( $f ) || is_link( $f ) ) {
				continue;
			}
			$g['scanned']++;
			$s['sig'] = $g;
			$s = self::sig_file( $s, $f );
			$g = $s['sig'];
		}
		if ( ! $g['files'] || $g['scanned'] >= self::MAX_SIG ) {
			if ( null === $g['dirs'] ) {
				$g['dirs'] = array();
			}
			while ( $g['dirs'] && ! self::out_of_time( $t0 ) && $g['scanned'] < self::MAX_SIG ) {
				$dir = array_pop( $g['dirs'] );
				list( $dirs, $files ) = self::list_dir( $dir );
				foreach ( $dirs as $d ) {
					$g['dirs'][] = $d;
				}
				foreach ( $files as $f ) {
					if ( $g['scanned'] >= self::MAX_SIG ) {
						break;
					}
					if ( ! self::is_php_ext( $f ) ) {
						continue;
					}
					$g['scanned']++;
					$s['sig'] = $g;
					$s = self::sig_file( $s, $f );
					$g = $s['sig'];
				}
			}
		}
		if ( $g['scanned'] >= self::MAX_SIG ) {
			$g['truncated'] = true;
		}
		$s['sig'] = $g;
		if ( ( ! $g['files'] && ! $g['dirs'] ) || $g['scanned'] >= self::MAX_SIG ) {
			$s['phase'] = 'done';
		}
		return $s;
	}

	/* ------------------------------------------------------------------ result */

	/** Entries the owner marked as expected: "kind|path#hash" ( the hash of the file when it was marked ). */
	public static function ignored() {
		$i = get_option( self::IGNORE, array() );
		return is_array( $i ) ? array_values( array_filter( array_map( 'strval', $i ) ) ) : array();
	}

	/** Marks an item as expected; a later change of the file shows it again ( the hash no longer matches ). */
	public static function ignore( $key ) {
		$list = self::ignored();
		if ( ! preg_match( '/^[a-z_]+\|[^\r\n|#]{1,300}$/', $key ) ) {
			return;
		}
		$r    = self::result();
		$hash = $r && isset( $r['hashes'][ $key ] ) ? $r['hashes'][ $key ] : 'x';
		$full = $key . '#' . $hash;
		if ( ! in_array( $full, $list, true ) && count( $list ) < 300 ) {
			$list[] = $full;
			update_option( self::IGNORE, $list, false );
		}
	}

	public static function unignore( $entry ) {
		update_option( self::IGNORE, array_values( array_diff( self::ignored(), array( $entry ) ) ), false );
	}

	/** Short fingerprint of the file behind an item ( 'x' when it does not exist ). */
	private static function file_hash( $kind, $it ) {
		if ( is_array( $it ) && isset( $it['slug'] ) ) {
			$abs = WP_PLUGIN_DIR . '/' . $it['slug'] . '/' . $it['path'];
		} else {
			$abs = self::to_abs( is_array( $it ) ? $it['path'] : $it );
		}
		$m = is_file( $abs ) ? @md5_file( $abs ) : false; // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return $m ? substr( $m, 0, 12 ) : 'x';
	}

	private static function finalize( $s ) {
		delete_option( self::STATE );
		delete_option( 'empedia_cloud_scan_core' );
		delete_option( 'empedia_cloud_scan_cur' );
		$prev = self::result();

		$sig = array();
		foreach ( $s['sig']['hits'] as $path => $codes ) {
			foreach ( $codes as $code ) {
				$sig[] = array( 'path' => $path, 'rule' => $code );
			}
		}
		$items = array(
			'core_modified'   => array_values( $s['core']['modified'] ),
			'core_missing'    => array_values( $s['core']['missing'] ),
			'core_extra'      => array_values( $s['core']['extra'] ),
			'root_extra'      => array_values( $s['core']['root_extra'] ),
			'plugin_modified' => array(),
			'plugin_extra'    => array(),
			'uploads_php'     => array_values( $s['uploads']['files'] ),
			'sig'             => $sig,
		);
		foreach ( $s['plugins']['modified'] as $slug => $files ) {
			foreach ( $files as $f ) {
				$items['plugin_modified'][] = array( 'slug' => $slug, 'path' => $f );
			}
		}
		foreach ( $s['plugins']['extra'] as $slug => $files ) {
			foreach ( $files as $f ) {
				$items['plugin_extra'][] = array( 'slug' => $slug, 'path' => $f );
			}
		}
		$hashes = array();
		foreach ( $items as $kind => $list ) {
			foreach ( array_slice( $list, 0, 600 ) as $it ) {
				$hashes[ self::item_key( $kind, $it ) ] = self::file_hash( $kind, $it );
			}
		}
		$result = array(
			'finished'      => time(),
			'started'       => (int) $s['started'],
			'error'         => isset( $s['error'] ) ? $s['error'] : '',
			'core'          => array( 'status' => $s['core']['status'], 'checked' => (int) $s['core']['checked'] ),
			'plugins'       => array( 'checked' => (int) $s['plugins']['checked'], 'no_checksums' => array_values( array_slice( $s['plugins']['no_checksums'], 0, 100 ) ) ),
			'sig_scanned'   => (int) $s['sig']['scanned'],
			'sig_truncated' => ! empty( $s['sig']['truncated'] ),
			'items'         => $items,
			'hashes'        => $hashes,
		);
		$result['fingerprint'] = self::fingerprint( $result );
		update_option( self::RESULT, $result, false );

		// Only findings that matter raise the alarm; missing files, extra files in plugins or in the root folder are listed but quiet.
		$alarm = self::count_issues( $result, true );
		if ( $alarm && ( ! $prev || ( isset( $prev['fingerprint'] ) ? $prev['fingerprint'] : '' ) !== $result['fingerprint'] ) && class_exists( 'Empedia_Cloud_Watch' ) ) {
			Empedia_Cloud_Watch::record( 'integrity', array( 'count' => $alarm ) );
		}
		Empedia_Cloud_Plugin::schedule_soon();
	}

	/** Items without those marked as expected. */
	public static function visible_items( $result ) {
		$ign    = array_flip( self::ignored() );
		$hashes = isset( $result['hashes'] ) && is_array( $result['hashes'] ) ? $result['hashes'] : array();
		$out    = array();
		foreach ( $result['items'] as $kind => $list ) {
			$out[ $kind ] = array();
			foreach ( $list as $it ) {
				$key = self::item_key( $kind, $it );
				$h   = isset( $hashes[ $key ] ) ? $hashes[ $key ] : 'x';
				if ( ! isset( $ign[ $key . '#' . $h ] ) ) {
					$out[ $kind ][] = $it;
				}
			}
		}
		return $out;
	}

	public static function item_key( $kind, $it ) {
		return $kind . '|' . ( is_array( $it ) ? ( isset( $it['slug'] ) ? $it['slug'] . '/' . $it['path'] : $it['path'] ) : $it );
	}

	/** @param bool $alarm_only count only the kinds that raise a notification */
	public static function count_issues( $result, $alarm_only = false ) {
		$n     = 0;
		$quiet = array( 'core_missing', 'root_extra', 'plugin_extra' );
		foreach ( self::visible_items( $result ) as $kind => $list ) {
			if ( $alarm_only && in_array( $kind, $quiet, true ) ) {
				continue;
			}
			$n += count( $list );
		}
		return $n;
	}

	private static function fingerprint( $result ) {
		$flat = array();
		foreach ( $result['items'] as $kind => $list ) {
			foreach ( $list as $it ) {
				$flat[] = self::item_key( $kind, $it ) . ( is_array( $it ) && isset( $it['rule'] ) ? '#' . $it['rule'] : '' );
			}
		}
		sort( $flat );
		return sha1( implode( "\n", $flat ) );
	}

	/** Compact summary for the inventory ( paths and rule codes only ). */
	public static function summary() {
		$r = self::result();
		if ( ! $r ) {
			return null;
		}
		$vis = self::visible_items( $r );
		$cap = function ( $list ) {
			return array_slice( $list, 0, self::CAP );
		};
		return array(
			'finished'     => (int) $r['finished'],
			'core_status'  => $r['core']['status'],
			'core_checked' => (int) $r['core']['checked'],
			'plugins_checked' => (int) $r['plugins']['checked'],
			'plugins_unverified' => count( $r['plugins']['no_checksums'] ),
			'sig_scanned'  => (int) $r['sig_scanned'],
			'sig_truncated' => (bool) $r['sig_truncated'],
			'ignored'      => count( self::ignored() ),
			'counts'       => array_map( 'count', $vis ),
			'core_modified' => $cap( $vis['core_modified'] ),
			'core_missing'  => $cap( $vis['core_missing'] ),
			'core_extra'    => $cap( $vis['core_extra'] ),
			'root_extra'    => $cap( $vis['root_extra'] ),
			'plugin_modified' => $cap( $vis['plugin_modified'] ),
			'plugin_extra'    => $cap( $vis['plugin_extra'] ),
			'uploads_php'   => $cap( $vis['uploads_php'] ),
			'signatures'    => $cap( $vis['sig'] ),
		);
	}
}
