<?php
/**
 * Collects the technical inventory of this site. Only versions, on/off settings and counts are collected –
 * never content, visitor data, user names, e-mail addresses or passwords. The cloud evaluates the result.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Inventory {

	/** Everything the cloud needs, as an array ready for JSON. */
	/**
	 * @param bool|string[] $with_probes true = run all probes, false = reuse stored results, array = run only these.
	 */
	public static function collect( $with_probes = true ) {
		global $wpdb;
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$db_info = method_exists( $wpdb, 'db_server_info' ) ? (string) $wpdb->db_server_info() : '';
		$db_type = false !== stripos( $db_info, 'mariadb' ) ? 'mariadb' : 'mysql';
		$db_ver  = method_exists( $wpdb, 'db_version' ) ? (string) $wpdb->db_version() : '';

		return array(
			'plugin_version'       => EMPEDIA_CLOUD_VERSION,
			'plugin_auto_update'   => in_array( plugin_basename( EMPEDIA_CLOUD_FILE ), (array) get_site_option( 'auto_update_plugins', array() ), true ),
			'wp_version'           => get_bloginfo( 'version' ),
			'php_version'          => PHP_VERSION,
			'db'                   => array( 'type' => $db_type, 'version' => $db_ver ),
			'locale'               => get_locale(),
			'multisite'            => is_multisite(),
			'server_software'      => isset( $_SERVER['SERVER_SOFTWARE'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ), 0, 80 ) : '',
			'core_update_available' => self::core_update_available(),
			'settings'             => self::settings( $with_probes ),
			'plugins'              => self::plugins(),
			'themes'               => self::themes(),
			'hardening_applied'    => Empedia_Cloud_Hardening::applied_map(),
			'integrity'            => Empedia_Cloud_Scanner::summary(),
			'firewall'             => Empedia_Cloud_Firewall::summary(),
			'last_backup'          => (int) get_option( 'empedia_cloud_last_backup', 0 ),
			'backup'               => Empedia_Cloud_Backup_Report::summary(),
			'modules'              => array(
				'hardening' => true,
				'login'     => ! Empedia_Cloud_Protect::off() && Empedia_Cloud_Protect::settings()['limit_on'],
				'captcha'   => self::captcha_active(),
				'scanner'   => (bool) Empedia_Cloud_Scanner::result(),
				'firewall'  => Empedia_Cloud_Firewall::summary()['enabled'],
			),
			'cron'                 => array(
				'disabled' => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
				'last_run' => (int) get_option( 'empedia_cloud_cron_seen', 0 ),
			),
		);
	}

	/** true / false, or null when WordPress has not checked yet. */
	public static function core_update_available() {
		$c = get_site_transient( 'update_core' );
		if ( ! is_object( $c ) || empty( $c->updates ) || ! is_array( $c->updates ) ) {
			return null;
		}
		$first = reset( $c->updates );
		return is_object( $first ) && isset( $first->response ) && 'upgrade' === $first->response;
	}

	public static function plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$all     = get_plugins();
		$active  = (array) get_option( 'active_plugins', array() );
		$network = is_multisite() ? array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) : array();
		$updates = get_site_transient( 'update_plugins' );
		$auto    = (array) get_site_option( 'auto_update_plugins', array() );
		$out     = array();
		foreach ( $all as $file => $data ) {
			$dir  = dirname( $file );
			$slug = '.' === $dir ? basename( $file, '.php' ) : $dir;
			$out[] = array(
				'slug'             => $slug,
				'name'             => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
				'version'          => isset( $data['Version'] ) ? (string) $data['Version'] : '',
				'active'           => in_array( $file, $active, true ) || in_array( $file, $network, true ),
				'update_available' => is_object( $updates ) && isset( $updates->response ) && isset( $updates->response[ $file ] ),
				'auto_update'      => in_array( $file, $auto, true ),
			);
		}
		return $out;
	}

	public static function themes() {
		$updates = get_site_transient( 'update_themes' );
		$active  = array( get_stylesheet(), get_template() );
		$out     = array();
		foreach ( wp_get_themes() as $slug => $theme ) {
			$out[] = array(
				'slug'             => (string) $slug,
				'name'             => (string) $theme->get( 'Name' ),
				'version'          => (string) $theme->get( 'Version' ),
				'active'           => in_array( $slug, $active, true ),
				'update_available' => is_object( $updates ) && isset( $updates->response ) && isset( $updates->response[ $slug ] ),
			);
		}
		return $out;
	}

	/**
	 * Settings as "problem present" booleans (true = problem), the same names the cloud rules use.
	 * Values that cannot be determined are omitted (the cloud then shows "unknown").
	 */
	public static function settings( $with_probes = true ) {
		$s = array();

		$s['ssl_off'] = 0 !== strpos( home_url(), 'https://' ) || 0 !== strpos( site_url(), 'https://' );

		$salts_bad = false;
		foreach ( array( 'AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT' ) as $k ) {
			if ( ! defined( $k ) ) {
				$salts_bad = true;
				break;
			}
			$v = (string) constant( $k );
			if ( strlen( $v ) < 32 || 'put your unique phrase here' === $v ) {
				$salts_bad = true;
				break;
			}
		}
		$s['salts_default'] = $salts_bad;

		$role                                = (string) get_option( 'default_role', 'subscriber' );
		$s['registration_privileged_role']   = (bool) get_option( 'users_can_register' ) && ! in_array( $role, array( 'subscriber', 'customer' ), true );
		$s['file_edit_enabled']              = ! ( defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT ) && ! Empedia_Cloud_Hardening::is_applied( 'file_edit' );
		$s['debug_display']                  = defined( 'WP_DEBUG' ) && WP_DEBUG && ( ! defined( 'WP_DEBUG_DISPLAY' ) || WP_DEBUG_DISPLAY );

		$admin = get_user_by( 'login', 'admin' );
		$s['default_admin_user'] = $admin && in_array( 'administrator', (array) $admin->roles, true );

		// What the site does by itself; our own filters are left out and an applied action is counted as fixed.
		$core = defined( 'WP_AUTO_UPDATE_CORE' ) && false === WP_AUTO_UPDATE_CORE ? false : true;
		$s['auto_update_core_minor'] = Empedia_Cloud_Hardening::is_applied( 'auto_update_core' ) ? true : (bool) Empedia_Cloud_Hardening::without_own_filters(
			function () use ( $core ) {
				return apply_filters( 'allow_minor_auto_core_updates', $core ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
			}
		);

		$perm = self::config_loose();
		if ( null !== $perm ) {
			$s['config_perms_loose'] = $perm;
		}

		$s['xmlrpc_enabled']    = Empedia_Cloud_Hardening::is_applied( 'xmlrpc' ) ? false : (bool) Empedia_Cloud_Hardening::without_own_filters(
			function () {
				return apply_filters( 'xmlrpc_enabled', true ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
			}
		);
		$s['generator_exposed'] = Empedia_Cloud_Hardening::is_applied( 'generator' ) ? false : ( Empedia_Cloud_Hardening::$generator_hooked || false !== has_action( 'wp_head', 'wp_generator' ) );
		if ( Empedia_Cloud_Hardening::is_applied( 'login_errors' ) ) {
			$s['login_errors_verbose'] = false;
		} elseif ( Empedia_Cloud_Hardening::$login_hooked || ! has_filter( 'login_errors' ) ) {
			$s['login_errors_verbose'] = true;
		}

		$q = new WP_User_Query( array( 'role' => 'administrator', 'fields' => 'ID', 'number' => 1, 'count_total' => true ) );
		$s['admins_count'] = (int) $q->get_total();

		$s['login_limit_off']  = Empedia_Cloud_Protect::off() || ! Empedia_Cloud_Protect::settings()['limit_on'];
		$s['admins_with_2fa']  = Empedia_Cloud_Protect::admins_with_factor();

		if ( defined( 'EMPEDIA_CLOUD_NO_PROBES' ) && EMPEDIA_CLOUD_NO_PROBES ) {
			return $s;
		}
		$probes = $with_probes ? Empedia_Cloud_Probes::run( true === $with_probes ? null : (array) $with_probes ) : Empedia_Cloud_Probes::stored();
		foreach ( $probes as $k => $v ) {
			$s[ $k ] = (bool) $v;
		}
		return $s;
	}

	/** Is the built-in bot protection ( EMPEDIAcaptcha ) available and configured? */
	public static function captcha_active() {
		$o = get_option( 'empedia_captcha', array() );
		return class_exists( 'Empedia_Captcha_Plugin' ) && is_array( $o ) && ! empty( $o['sitekey'] ) && ! empty( $o['secret'] );
	}

	/** true when wp-config.php is readable by "others"; null when unknown (Windows, file not found). */
	public static function config_loose() {
		if ( '\\' === DIRECTORY_SEPARATOR ) {
			return null;
		}
		$file = ABSPATH . 'wp-config.php';
		if ( ! file_exists( $file ) ) {
			$file = dirname( untrailingslashit( ABSPATH ) ) . '/wp-config.php';
		}
		if ( ! file_exists( $file ) ) {
			return null;
		}
		$perms = @fileperms( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		return false === $perms ? null : ( ( $perms & 0004 ) !== 0 );
	}
}

/**
 * Measurements through requests to this very site (loopback), made by the daily job – so the result is what visitors
 * actually get, whichever web server is in use. Hosts that block loopback requests simply yield "unknown".
 */
class Empedia_Cloud_Probes {

	const OPTION = 'empedia_cloud_probes';

	/** Details of the last measurement per probe (HTTP code, host, cache headers; no content) – shown when a setting stays open. */
	const INFO = 'empedia_cloud_probe_info';

	/** Details of the most recent loopback request (set by get()). */
	private static $last = null;

	/** Probe name → method. */
	private static function map() {
		return array(
			'uploads_php_exec'         => array( __CLASS__, 'uploads_php_exec' ),
			'debug_log_exposed'        => array( __CLASS__, 'debug_log_exposed' ),
			'rest_users_public'        => array( __CLASS__, 'rest_users_public' ),
			'security_headers_missing' => array( __CLASS__, 'security_headers_missing' ),
			'author_enum'              => array( __CLASS__, 'author_enum' ),
		);
	}

	/** Probe belonging to a hardening action (the others keep their last result). */
	public static function for_action( $action ) {
		$m = array(
			'uploads_php'      => 'uploads_php_exec',
			'debug_log'        => 'debug_log_exposed',
			'rest_users'       => 'rest_users_public',
			'security_headers' => 'security_headers_missing',
			'author_enum'      => 'author_enum',
		);
		return isset( $m[ $action ] ) ? array( $m[ $action ] ) : array();
	}

	/** Last stored results (probe name → bool; unknown ones are missing). */
	public static function stored() {
		$s = get_option( self::OPTION, array() );
		return is_array( $s ) ? $s : array();
	}

	/**
	 * Runs the given probes (all when null), stores the results and returns every stored result.
	 *
	 * @param string[]|null $only Probe names.
	 * @return array<string,bool>
	 */
	public static function run( $only = null ) {
		$stored = self::stored();
		foreach ( self::map() as $name => $cb ) {
			if ( null !== $only && ! in_array( $name, $only, true ) ) {
				continue;
			}
			self::$last = null;
			$v          = call_user_func( $cb );
			if ( null === $v ) {
				unset( $stored[ $name ] );
			} else {
				$stored[ $name ] = (bool) $v;
			}
			if ( is_array( self::$last ) ) {
				$info          = self::info();
				$info[ $name ] = self::$last + array( 'result' => null === $v ? 'unknown' : ( $v ? 'open' : 'closed' ), 'at' => time() );
				update_option( self::INFO, $info, false );
			}
		}
		update_option( self::OPTION, $stored, false );
		return $stored;
	}

	/** @return array<string,array> */
	public static function info() {
		$i = get_option( self::INFO, array() );
		return is_array( $i ) ? $i : array();
	}

	/**
	 * Loopback request. Every call carries a unique query argument and "no-cache" headers: page caches, CDNs and server caches
	 * key by the full address, so without it a measurement taken right after the setting was changed would be answered with the
	 * copy stored by the previous measurement (the old state) and a correctly applied action would keep showing as open.
	 */
	private static function get( $url, $method = 'GET', $bust = true ) {
		if ( $bust ) {
			$url = add_query_arg( 'empedia_probe', wp_generate_password( 10, false, false ), $url );
		}
		$res = wp_remote_request(
			$url,
			array(
				'method'      => $method,
				'timeout'     => 4,
				'redirection' => 0,
				'sslverify'   => apply_filters( 'https_local_ssl_verify', false ), // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
				'headers'     => array(
					'User-Agent'    => 'EMPEDIAcloud-WordPress/' . EMPEDIA_CLOUD_VERSION,
					'Cache-Control' => 'no-cache, no-store, max-age=0',
					'Pragma'        => 'no-cache',
				),
				'cookies'     => array(),
			)
		);
		self::$last = self::describe( $url, $res );
		return $res;
	}

	/** Kept for the "measure again" hint: only codes and the names/values of cache related headers, never content. */
	private static function describe( $url, $res ) {
		$d = array( 'host' => (string) wp_parse_url( $url, PHP_URL_HOST ) );
		if ( is_wp_error( $res ) ) {
			$d['code'] = 0;
			return $d;
		}
		$d['code'] = (int) wp_remote_retrieve_response_code( $res );
		$h         = wp_remote_retrieve_headers( $res );
		$h         = array_change_key_case( (array) ( is_object( $h ) && method_exists( $h, 'getAll' ) ? $h->getAll() : $h ), CASE_LOWER );
		$cache     = array();
		foreach ( array( 'x-cache', 'x-cache-status', 'cf-cache-status', 'x-litespeed-cache', 'x-wp-rocket', 'x-varnish', 'x-proxy-cache', 'age', 'via', 'server' ) as $k ) {
			if ( isset( $h[ $k ] ) ) {
				$v = is_array( $h[ $k ] ) ? implode( ',', $h[ $k ] ) : (string) $h[ $k ];
				$cache[ $k ] = substr( preg_replace( '/[^\x20-\x7e]/', '', $v ), 0, 60 );
			}
		}
		$d['cache'] = $cache;
		return $d;
	}

	/** Writes a harmless PHP file into the uploads folder, requests it and deletes it again: true = it was executed. */
	public static function uploads_php_exec() {
		$up = wp_upload_dir( null, false );
		if ( empty( $up['basedir'] ) || ! is_dir( $up['basedir'] ) || ! wp_is_writable( $up['basedir'] ) ) {
			return null;
		}
		if ( wp_parse_url( $up['baseurl'], PHP_URL_HOST ) !== wp_parse_url( home_url(), PHP_URL_HOST ) ) {
			return null; // uploads served from another host (CDN): not measurable here
		}
		foreach ( (array) glob( trailingslashit( $up['basedir'] ) . 'empedia-probe-*.php' ) as $old ) { // leftovers of an aborted run
			if ( @filemtime( $old ) < time() - 300 ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				@unlink( $old ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			}
		}
		$name = 'empedia-probe-' . wp_generate_password( 12, false, false ) . '.php';
		$path = trailingslashit( $up['basedir'] ) . $name;
		// The file only prints a marker that is not contained literally in the source (so a server that shows the source does not match).
		if ( false === @file_put_contents( $path, "<?php echo 'EMPEDIA' . '-PROBE';" ) ) { // phpcs:ignore WordPress.WP.AlternativeFunctions
			return null;
		}
		try {
			$res = self::get( trailingslashit( $up['baseurl'] ) . $name, 'GET', false ); // the random file name is unique already
			if ( is_wp_error( $res ) ) {
				return null;
			}
			return 'EMPEDIA-PROBE' === trim( (string) wp_remote_retrieve_body( $res ) );
		} finally {
			@unlink( $path ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
	}

	/**
	 * Result of the debug.log request. true = readable from outside, false = not, null = cannot tell
	 * (redirect, server error, method not allowed …).
	 */
	public static function eval_debug_log( $code ) {
		$code = (int) $code;
		if ( 200 === $code || 206 === $code ) {
			return true;
		}
		return in_array( $code, array( 401, 403, 404, 410 ), true ) ? false : null;
	}

	public static function debug_log_exposed() {
		$res = self::get( content_url( '/debug.log' ), 'HEAD' );
		if ( is_wp_error( $res ) ) {
			return null;
		}
		return self::eval_debug_log( wp_remote_retrieve_response_code( $res ) );
	}

	/**
	 * Result of the user list request. true = names are listed publicly, false = not (401/403/404/410, or an answer that is not
	 * a list of users), null = cannot tell (redirect, server error …).
	 */
	public static function eval_rest_users( $code, $body ) {
		$code = (int) $code;
		if ( 200 !== $code ) {
			return in_array( $code, array( 401, 403, 404, 410 ), true ) ? false : null;
		}
		$json = json_decode( (string) $body, true );
		if ( ! is_array( $json ) || ! $json || array_keys( $json ) !== range( 0, count( $json ) - 1 ) ) {
			return false; // empty list, an error object or something else: no user names are exposed
		}
		foreach ( $json as $u ) {
			if ( is_array( $u ) && ( isset( $u['slug'] ) || isset( $u['name'] ) ) ) {
				return true;
			}
		}
		return false;
	}

	public static function rest_users_public() {
		$res = self::get( rest_url( 'wp/v2/users' ) );
		if ( is_wp_error( $res ) ) {
			return null;
		}
		return self::eval_rest_users( wp_remote_retrieve_response_code( $res ), wp_remote_retrieve_body( $res ) );
	}

	/** Result of the security headers request: true = a header is missing, null = cannot tell (redirect, error). */
	public static function eval_security_headers( $code, $headers ) {
		$code = (int) $code;
		if ( $code < 200 || $code >= 300 ) {
			return null;
		}
		$h       = array_change_key_case( (array) ( is_object( $headers ) && method_exists( $headers, 'getAll' ) ? $headers->getAll() : $headers ), CASE_LOWER );
		$nosniff = ! empty( $h['x-content-type-options'] );
		$frame   = ! empty( $h['x-frame-options'] ) || ( ! empty( $h['content-security-policy'] ) && false !== stripos( (string) ( is_array( $h['content-security-policy'] ) ? implode( ' ', $h['content-security-policy'] ) : $h['content-security-policy'] ), 'frame-ancestors' ) );
		return ! ( $nosniff && $frame );
	}

	public static function security_headers_missing() {
		$res = self::get( home_url( '/' ), 'HEAD' );
		if ( is_wp_error( $res ) ) {
			return null;
		}
		return self::eval_security_headers( wp_remote_retrieve_response_code( $res ), wp_remote_retrieve_headers( $res ) );
	}

	/** Result of the ?author=1 request: true = redirects to /author/<name>/ (user name revealed), false = nothing revealed (also 404: no such user), null = cannot tell (server error …). */
	public static function eval_author_enum( $code, $location ) {
		$code = (int) $code;
		if ( in_array( $code, array( 301, 302, 307, 308 ), true ) ) {
			return false !== stripos( (string) $location, '/author/' );
		}
		if ( in_array( $code, array( 401, 403, 404, 410 ), true ) ) {
			return false; // blocked, or no such user: nothing is revealed
		}
		return $code >= 200 && $code < 300 ? false : null;
	}

	/**
	 * User ids to try for the "?author=" measurement: 1 (the classic guess) plus a few real ones from the local user table
	 * (authors with published posts first, then administrators). Only numbers are read, no names.
	 *
	 * @return int[]
	 */
	public static function author_ids() {
		$ids = array( 1 );
		$q   = array(
			'number'  => 3,
			'fields'  => 'ID',
			'orderby' => 'ID',
			'order'   => 'ASC',
		);
		foreach ( array( array( 'has_published_posts' => true ), array( 'role' => 'administrator' ) ) as $extra ) {
			foreach ( (array) get_users( $q + $extra ) as $id ) {
				$ids[] = (int) $id;
			}
		}
		return array_slice( array_values( array_unique( array_filter( $ids ) ) ), 0, 4 );
	}

	/**
	 * Combines the single answers: one revealed name is enough for "open"; "closed" needs at least one clear answer and none open;
	 * only unclear answers stay unknown.
	 *
	 * @param array<int,bool|null> $results
	 */
	public static function combine_author_results( array $results ) {
		if ( in_array( true, $results, true ) ) {
			return true;
		}
		return in_array( false, $results, true ) ? false : null;
	}

	public static function author_enum() {
		$results = array();
		foreach ( self::author_ids() as $id ) {
			$res = self::get( add_query_arg( 'author', (string) $id, home_url( '/' ) ), 'HEAD' );
			$results[] = is_wp_error( $res ) ? null : self::eval_author_enum( wp_remote_retrieve_response_code( $res ), wp_remote_retrieve_header( $res, 'location' ) );
		}
		return self::combine_author_results( $results );
	}
}
