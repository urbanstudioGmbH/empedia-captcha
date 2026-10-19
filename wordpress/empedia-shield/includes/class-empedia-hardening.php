<?php
/**
 * Security settings the plugin can apply and revert. Every action is reversible, nothing touches wp-config.php,
 * and file based actions only write a clearly marked block ("EMPEDIAcloud") into an .htaccess file.
 * Which problems exist is decided by the cloud; this class only knows how to secure the ones marked "plugin".
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Hardening {

	const OPTION = 'empedia_cloud_hardening';
	const MARKER = 'EMPEDIAcloud';

	/** Set when this request already registered the hook (so a revert in the same request is reported correctly). */
	public static $generator_hooked = false;
	public static $login_hooked     = false;

	/** Actions the cloud knows (key = action name used in the cloud rules). */
	public static function actions() {
		return array(
			'uploads_php',
			'file_edit',
			'debug_log',
			'rest_users',
			'auto_update_core',
			'security_headers',
			'xmlrpc',
			'author_enum',
			'generator',
			'login_errors',
		);
	}

	/** Action → timestamp it was applied. */
	public static function applied_map() {
		$m = get_option( self::OPTION, array() );
		if ( ! is_array( $m ) ) {
			return array();
		}
		$out = array();
		foreach ( $m as $k => $t ) {
			if ( in_array( $k, self::actions(), true ) && (int) $t > 0 ) {
				$out[ $k ] = (int) $t;
			}
		}
		return $out;
	}

	public static function is_applied( $action ) {
		$m = self::applied_map();
		return isset( $m[ $action ] );
	}

	/**
	 * Applies an action.
	 *
	 * @return true|WP_Error
	 */
	public static function apply( $action ) {
		if ( ! in_array( $action, self::actions(), true ) ) {
			return new WP_Error( 'empedia_unknown_action', __( 'Unknown action.', 'empedia-shield' ) );
		}
		if ( in_array( $action, array( 'uploads_php', 'debug_log' ), true ) ) {
			$r = self::write_block( $action, true );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
		}
		$m            = self::applied_map();
		$m[ $action ] = time();
		update_option( self::OPTION, $m, false );
		return true;
	}

	/** @return true|WP_Error */
	public static function revert( $action ) {
		if ( ! in_array( $action, self::actions(), true ) ) {
			return new WP_Error( 'empedia_unknown_action', __( 'Unknown action.', 'empedia-shield' ) );
		}
		if ( in_array( $action, array( 'uploads_php', 'debug_log' ), true ) ) {
			$r = self::write_block( $action, false );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
		}
		$m = self::applied_map();
		unset( $m[ $action ] );
		update_option( self::OPTION, $m, false );
		return true;
	}

	/** Removes all blocks and settings (uninstall). */
	public static function revert_all() {
		foreach ( array( 'uploads_php', 'debug_log' ) as $a ) {
			self::write_block( $a, false );
		}
		delete_option( self::OPTION );
	}

	/** File that holds the block for an action. */
	private static function target_file( $action ) {
		if ( 'uploads_php' === $action ) {
			$up = wp_upload_dir( null, false );
			return empty( $up['basedir'] ) ? '' : trailingslashit( $up['basedir'] ) . '.htaccess';
		}
		return trailingslashit( WP_CONTENT_DIR ) . '.htaccess';
	}

	private static function block_lines( $action ) {
		if ( 'uploads_php' === $action ) {
			return array(
				'# uploads_php: no script execution in the uploads folder',
				'<IfModule mod_authz_core.c>',
				'<FilesMatch "(?i)\.(php[0-9]?|phtml|phar|pht|phps)$">',
				'Require all denied',
				'</FilesMatch>',
				'</IfModule>',
				'<IfModule !mod_authz_core.c>',
				'<FilesMatch "(?i)\.(php[0-9]?|phtml|phar|pht|phps)$">',
				'Order allow,deny',
				'Deny from all',
				'</FilesMatch>',
				'</IfModule>',
			);
		}
		return array(
			'# debug_log: no public access to debug logs',
			'<IfModule mod_authz_core.c>',
			'<FilesMatch "^(debug\.log|debug[_-]log(\.txt)?|error[_-]log(\.txt)?)$">',
			'Require all denied',
			'</FilesMatch>',
			'</IfModule>',
			'<IfModule !mod_authz_core.c>',
			'<FilesMatch "^(debug\.log|debug[_-]log(\.txt)?|error[_-]log(\.txt)?)$">',
			'Order allow,deny',
			'Deny from all',
			'</FilesMatch>',
			'</IfModule>',
		);
	}

	/**
	 * Writes or removes the marked block. Several actions can share one file, so the marker contains the action name.
	 *
	 * @return true|WP_Error
	 */
	private static function write_block( $action, $add ) {
		if ( ! function_exists( 'insert_with_markers' ) ) {
			require_once ABSPATH . 'wp-admin/includes/misc.php';
			require_once ABSPATH . 'wp-admin/includes/file.php';
		}
		$file = self::target_file( $action );
		if ( '' === $file ) {
			return new WP_Error( 'empedia_no_file', __( 'The folder could not be determined.', 'empedia-shield' ) );
		}
		if ( ! $add && ! file_exists( $file ) ) {
			return true;
		}
		$dir = dirname( $file );
		if ( ! is_dir( $dir ) || ! wp_is_writable( $dir ) || ( file_exists( $file ) && ! wp_is_writable( $file ) ) ) {
			return new WP_Error( 'empedia_not_writable', __( 'The file could not be written. Please check the permissions of the folder.', 'empedia-shield' ) );
		}
		if ( ! $add ) {
			return self::remove_block( $file, self::MARKER . '-' . $action );
		}
		$ok = insert_with_markers( $file, self::MARKER . '-' . $action, self::block_lines( $action ) );
		if ( ! $ok ) {
			return new WP_Error( 'empedia_write_failed', __( 'The file could not be written. Please check the permissions of the folder.', 'empedia-shield' ) );
		}
		return true;
	}

	/** Removes the marked block completely (including its marker lines); an .htaccess that becomes empty is deleted. */
	private static function remove_block( $file, $marker ) {
		$content = (string) file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$clean   = preg_replace( '/\n?# BEGIN ' . preg_quote( $marker, '/' ) . '\b.*?# END ' . preg_quote( $marker, '/' ) . '\n?/s', "\n", $content );
		$clean   = null === $clean ? $content : trim( $clean );
		if ( $clean === trim( $content ) ) {
			return true;
		}
		if ( '' === $clean ) {
			return @unlink( $file ) ? true : new WP_Error( 'empedia_write_failed', __( 'The file could not be written. Please check the permissions of the folder.', 'empedia-shield' ) ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		}
		return false === file_put_contents( $file, $clean . "\n" ) ? new WP_Error( 'empedia_write_failed', __( 'The file could not be written. Please check the permissions of the folder.', 'empedia-shield' ) ) : true; // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/** Registers the runtime hooks of all applied actions. Called on every request, so it must stay cheap. */
	public static function bootstrap() {
		$m = self::applied_map();
		if ( ! $m ) {
			return;
		}
		if ( isset( $m['file_edit'] ) ) {
			add_filter( 'map_meta_cap', array( __CLASS__, 'block_file_edit' ), 10, 2 );
		}
		if ( isset( $m['rest_users'] ) ) {
			add_filter( 'rest_endpoints', array( __CLASS__, 'hide_rest_users' ) );
		}
		if ( isset( $m['auto_update_core'] ) ) {
			add_filter( 'allow_minor_auto_core_updates', array( __CLASS__, 'yes' ), 99 );
		}
		if ( isset( $m['security_headers'] ) ) {
			add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ) );
		}
		if ( isset( $m['xmlrpc'] ) ) {
			add_filter( 'xmlrpc_enabled', array( __CLASS__, 'no' ), 99 );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'no_methods' ), 99 );
			add_filter( 'wp_headers', array( __CLASS__, 'drop_pingback_header' ) );
		}
		if ( isset( $m['author_enum'] ) ) {
			add_action( 'template_redirect', array( __CLASS__, 'block_author_enum' ), 0 );
			add_filter( 'wp_sitemaps_add_provider', array( __CLASS__, 'drop_users_sitemap' ), 10, 2 );
		}
		if ( isset( $m['generator'] ) ) {
			self::$generator_hooked = true;
			remove_action( 'wp_head', 'wp_generator' );
			add_filter( 'the_generator', '__return_empty_string', 99 );
		}
		if ( isset( $m['login_errors'] ) ) {
			self::$login_hooked = true;
			add_filter( 'login_errors', array( __CLASS__, 'uniform_login_error' ), 99 );
		}
	}

	public static function yes() {
		return true;
	}

	public static function no() {
		return false;
	}

	/** No XML-RPC methods at all (also none that work without logging in, e.g. system.multicall). */
	public static function no_methods() {
		return array();
	}

	/**
	 * What the site would do without our own filters (for the report): runs the callback with our filters removed,
	 * so a setting that was just reverted is not reported as still fixed.
	 *
	 * @param callable $cb Callback.
	 * @return mixed
	 */
	public static function without_own_filters( $cb ) {
		$had_x = remove_filter( 'xmlrpc_enabled', array( __CLASS__, 'no' ), 99 );
		$had_a = remove_filter( 'allow_minor_auto_core_updates', array( __CLASS__, 'yes' ), 99 );
		try {
			return call_user_func( $cb );
		} finally {
			if ( $had_x ) {
				add_filter( 'xmlrpc_enabled', array( __CLASS__, 'no' ), 99 );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'no_methods' ), 99 );
			}
			if ( $had_a ) {
				add_filter( 'allow_minor_auto_core_updates', array( __CLASS__, 'yes' ), 99 );
			}
		}
	}

	public static function block_file_edit( $caps, $cap ) {
		if ( in_array( $cap, array( 'edit_themes', 'edit_plugins', 'edit_files' ), true ) ) {
			$caps[] = 'do_not_allow';
		}
		return $caps;
	}

	public static function hide_rest_users( $endpoints ) {
		if ( ! is_user_logged_in() ) {
			unset( $endpoints['/wp/v2/users'], $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}
		return $endpoints;
	}

	public static function send_security_headers() {
		if ( is_admin() || headers_sent() ) {
			return;
		}
		$sent = array_map( 'strtolower', array_map( function ( $h ) {
			return strtok( $h, ':' );
		}, headers_list() ) );
		if ( ! in_array( 'x-content-type-options', $sent, true ) ) {
			header( 'X-Content-Type-Options: nosniff' );
		}
		if ( ! in_array( 'x-frame-options', $sent, true ) ) {
			header( 'X-Frame-Options: SAMEORIGIN' );
		}
		if ( ! in_array( 'referrer-policy', $sent, true ) ) {
			header( 'Referrer-Policy: strict-origin-when-cross-origin' );
		}
	}

	public static function drop_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public static function block_author_enum() {
		if ( is_admin() || ! get_option( 'permalink_structure' ) || ! isset( $_GET['author'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification
			return;
		}
		$v = wp_unslash( $_GET['author'] ); // phpcs:ignore WordPress.Security.NonceVerification, WordPress.Security.ValidatedSanitizedInput
		if ( is_string( $v ) && ctype_digit( $v ) ) {
			wp_safe_redirect( home_url( '/' ), 302 );
			exit;
		}
	}

	public static function drop_users_sitemap( $provider, $name ) {
		return 'users' === $name ? false : $provider;
	}

	public static function uniform_login_error( $errors = '' ) {
		global $action;
		if ( isset( $action ) && 'login' !== $action ) {
			return $errors; // lost password, registration, reset: keep the specific messages
		}
		return __( '<strong>Error:</strong> The login details are incorrect.', 'empedia-shield' );
	}
}
