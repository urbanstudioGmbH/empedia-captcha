<?php
/**
 * Firewall ( rule set, observe mode first ). It inspects the request very early, before WordPress and most plugins act on it.
 *
 *  - Every rule class starts in OBSERVE mode: matches are only counted and a few samples are kept. A class can be switched to
 *    ENFORCE ( answer 403 ) after at least 72 hours of observation, so false positives are seen before they hurt a visitor.
 *  - Emergency exits: the constant EMPEDIA_CLOUD_FIREWALL_OFF in wp-config.php, and the switch in EMPEDIAcloud ( pause / observe only ).
 *  - A class that blocks absurdly many requests in a minute pauses itself ( the rule is probably wrong ).
 *  - It fails open: an error in the firewall never takes the site down.
 *  - IP addresses are never stored; samples contain the rule, the field name and a short excerpt of the matched text.
 *
 * This file must work when it is loaded as a must-use plugin, before most WordPress functions exist: only core functions of
 * functions.php / plugin.php / the options API and $wpdb are used here.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Empedia_Cloud_Firewall', false ) ) {

class Empedia_Cloud_Firewall {

	const OPTION  = 'empedia_cloud_fw';
	const REMOTE  = 'empedia_cloud_fw_remote';
	const SAMPLES = 'empedia_cloud_fw_samples';
	const CNT     = 'empedia_fw_cnt_';
	const MIN_OBSERVE = 259200; // 72 hours
	const MAX_VALUE   = 32768;
	const MAX_BUDGET  = 262144; // bytes inspected per request ( more is passed through: fail open )
	const MAX_VALUES  = 300;

	private static $booted = false;
	private static $now_blocked = false;

	/** @return array class => array( rule id => array( 'targets' => …, 'regex' => … ) ) */
	public static function rules() {
		return array(
			'sqli'    => array(
				'sqli_union'  => array( 'all', '/\bunion\b[\s\/\*\(+]*(?:(?:all|distinct)\b[\s\/\*]*)?select\b/i' ),
				'sqli_schema' => array( 'all', '/\binformation_schema\b|\bmysql\.user\b|\bsys\.tables\b/i' ),
				'sqli_time'   => array( 'all', '/\b(?:sleep|pg_sleep)\s*\(\s*\d+(?:\.\d+)?\s*\)|\bbenchmark\s*\(\s*\d+\s*,|\bwaitfor\s+delay\b/i' ),
				'sqli_tauto'  => array( 'all', '/[\'"]\s*(?:or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+|[\'"]\s*or\s+[\'"][^\'"]*[\'"]\s*=\s*[\'"]/i' ),
				'sqli_stack'  => array( 'all', '/;\s*(?:drop\s+(?:table|database|schema|user)|truncate\s+table|delete\s+from|insert\s+into|alter\s+(?:table|user))\b/i' ),
				'sqli_file'   => array( 'all', '/\b(?:load_file|into\s+(?:out|dump)file)\b/i' ),
				'sqli_fn'     => array( 'all', '/\b(?:extractvalue|updatexml)\s*\(|\bgroup_concat\s*\(/i' ),
			),
			'xss'     => array(
				'xss_script'  => array( 'all', '/<\s*script\b|<\s*\/\s*script\b/i' ),
				'xss_handler' => array( 'all', '/<[a-z][^>]{0,200}\son(?:error|load|click|mouseover|focus|toggle|animationstart)\s*=/i' ),
				'xss_jsuri'   => array( 'all', '/^\s*(?:javascript|vbscript)\s*:|(?:href|src|action|formaction)\s*=\s*["\']?\s*(?:javascript|vbscript|data:text\/html)\s*:/i' ),
				'xss_embed'   => array( 'all', '/<\s*(?:iframe|object|embed|svg|math)\b[^>]*(?:src|onload|data)\s*=/i' ),
			),
			'lfi'     => array(
				'lfi_traversal' => array( 'all', '/(?:\.\.[\/\\\\]){2,}|(?:%2e%2e[\/\\\\%]){2}/i' ),
				'lfi_sensitive' => array( 'values', '/\/etc\/(?:passwd|shadow|hosts)|\bboot\.ini\b|\bwin\.ini\b|\/proc\/self\/environ|[\/\\\\]wp-config\.php(?:\.\w+)?\b/i' ),
				'lfi_wrapper'   => array( 'values', '/\b(?:php|phar|zip|expect|glob|gopher|dict):\/\/|\bfile:\/\/\/|\bdata:\/\/text/i' ),
			),
			'upload'  => array(
				'upload_php' => array( 'files', '/\.(?:php\d?|phtml|phar|pht|phps|shtml|cgi|pl|py|asp|aspx|jsp)(?:\.|$)|^\.(?:htaccess|user\.ini)$/i' ),
			),
			'scanner' => array(
				'scanner_ua' => array( 'ua', '/\b(?:sqlmap|nikto|acunetix|netsparker|nessus|openvas|havij|w3af|dirbuster|gobuster|ffuf|wfuzz|masscan|zgrab|nuclei|wpscan|jaeles|arachni|skipfish|appscan)\b/i' ),
			),
			'probe'   => array(
				'probe_paths' => array( 'path', '#(?:/\.git(?:/|$)|/\.svn(?:/|$)|/\.env(?:\.|$)|/\.DS_Store|/wp-config\.(?:php\.|bak|old|txt|orig|save)|/phpinfo\.php|/adminer\.php|\.sql(?:\.gz)?$|/backup\.(?:zip|tar|sql)|/vendor/phpunit|eval-stdin\.php|/cgi-bin/|/(?:shell|c99|wso|r57)\.php)#i' ),
			),
			'xmlrpc'  => array(
				'xmlrpc_multicall' => array( 'special', '' ),
			),
			'rate'    => array(
				'rate_login'  => array( 'special', '' ),
				'rate_xmlrpc' => array( 'special', '' ),
			),
			'ip'      => array(
				'ip_block'      => array( 'special', '' ),
				'country_block' => array( 'special', '' ),
			),
		);
	}

	public static function classes() {
		return array_keys( self::rules() );
	}

	public static function rule_ids() {
		$ids = array();
		foreach ( self::rules() as $cls => $list ) {
			foreach ( array_keys( $list ) as $id ) {
				$ids[ $id ] = $cls;
			}
		}
		return $ids;
	}

	/* ------------------------------------------------------------------ settings */

	public static function defaults() {
		$modes = array();
		foreach ( self::classes() as $c ) {
			$modes[ $c ] = 'ip' === $c ? 'enforce' : 'observe';
		}
		return array(
			'enabled'         => false,
			'modes'           => $modes,
			'since'           => array(),
			'allow_ips'       => '',
			'block_ips'       => '',
			'allow_countries' => '',
			'block_countries' => '',
			'exceptions'      => array(),
		);
	}

	public static function settings() {
		$o = get_option( self::OPTION, array() );
		$d = self::defaults();
		$o = is_array( $o ) ? array_merge( $d, $o ) : $d;
		$o['modes'] = is_array( $o['modes'] ) ? array_merge( $d['modes'], $o['modes'] ) : $d['modes'];
		foreach ( $o['modes'] as $c => $m ) {
			if ( ! in_array( $m, array( 'off', 'observe', 'enforce' ), true ) ) {
				$o['modes'][ $c ] = 'observe';
			}
		}
		$o['enabled']    = (bool) $o['enabled'];
		$o['since']      = is_array( $o['since'] ) ? $o['since'] : array();
		$o['exceptions'] = is_array( $o['exceptions'] ) ? array_values( array_filter( array_map( 'strval', $o['exceptions'] ) ) ) : array();
		return $o;
	}

	/** Remote switch from EMPEDIAcloud: array( 'switch' => ''|'off'|'observe', 'rules_off' => string[] ). */
	public static function remote() {
		$r = get_option( self::REMOTE, array() );
		$r = is_array( $r ) ? $r : array();
		return array(
			'switch'    => isset( $r['switch'] ) && in_array( $r['switch'], array( 'off', 'observe' ), true ) ? $r['switch'] : '',
			'rules_off' => isset( $r['rules_off'] ) && is_array( $r['rules_off'] ) ? array_values( array_intersect( array_map( 'strval', $r['rules_off'] ), array_keys( self::rule_ids() ) ) ) : array(),
		);
	}

	/** Takes over the emergency switch and the disabled rules from an answer of the cloud ( heartbeat, inventory, status ). */
	public static function apply_remote( $response ) {
		if ( ! is_array( $response ) || ! isset( $response['firewall'] ) || ! is_array( $response['firewall'] ) ) {
			return;
		}
		$f   = $response['firewall'];
		$new = array(
			'switch'    => isset( $f['switch'] ) && in_array( $f['switch'], array( 'off', 'observe' ), true ) ? $f['switch'] : '',
			'rules_off' => isset( $f['rules_off'] ) && is_array( $f['rules_off'] ) ? array_values( array_intersect( array_map( 'strval', $f['rules_off'] ), array_keys( self::rule_ids() ) ) ) : array(),
		);
		if ( get_option( self::REMOTE, array() ) !== $new ) {
			update_option( self::REMOTE, $new, false );
		}
	}

	public static function off_by_constant() {
		return defined( 'EMPEDIA_CLOUD_FIREWALL_OFF' ) && EMPEDIA_CLOUD_FIREWALL_OFF;
	}

	/** Effective mode of a class right now: off | observe | enforce. */
	public static function mode_of( $cls, $s = null ) {
		$s = null === $s ? self::settings() : $s;
		if ( self::off_by_constant() || ! $s['enabled'] ) {
			return 'off';
		}
		$m  = isset( $s['modes'][ $cls ] ) ? $s['modes'][ $cls ] : 'observe';
		$rm = self::remote();
		if ( 'off' === $rm['switch'] ) {
			return 'off';
		}
		if ( 'observe' === $rm['switch'] && 'enforce' === $m ) {
			$m = 'observe';
		}
		if ( 'enforce' === $m && get_transient( 'empedia_fw_pause_' . $cls ) ) {
			$m = 'observe'; // paused after a flood of blocks
		}
		return $m;
	}

	/* ------------------------------------------------------------------ request */

	public static function client_ip() {
		$ip  = isset( $_SERVER['REMOTE_ADDR'] ) ? (string) $_SERVER['REMOTE_ADDR'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$src = get_option( 'empedia_cloud_protect', array() );
		$src = is_array( $src ) && isset( $src['ip_source'] ) ? $src['ip_source'] : 'remote';
		$map = array( 'xff' => 'HTTP_X_FORWARDED_FOR', 'cf' => 'HTTP_CF_CONNECTING_IP', 'real' => 'HTTP_X_REAL_IP' );
		if ( isset( $map[ $src ] ) && ! empty( $_SERVER[ $map[ $src ] ] ) ) {
			$v = (string) $_SERVER[ $map[ $src ] ]; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( 'xff' === $src ) {
				$p = array_map( 'trim', explode( ',', $v ) );
				$v = end( $p );
			}
			if ( filter_var( trim( $v ), FILTER_VALIDATE_IP ) ) {
				$ip = trim( $v );
			}
		}
		if ( preg_match( '/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i', $ip, $m ) ) {
			$ip = $m[1];
		}
		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '0.0.0.0';
	}

	private static function ip_is_public( $ip ) {
		return (bool) filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE );
	}

	public static function ip_in( $ip, $list ) {
		foreach ( preg_split( '/[\s,;]+/', (string) $list, -1, PREG_SPLIT_NO_EMPTY ) as $entry ) {
			if ( $entry === $ip ) {
				return true;
			}
			if ( false !== strpos( $entry, '/' ) ) {
				list( $net, $bits ) = explode( '/', $entry, 2 );
				$a = @inet_pton( $net ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$b = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$n = (int) $bits;
				if ( false === $a || false === $b || strlen( $a ) !== strlen( $b ) || $n < 0 || $n > 8 * strlen( $a ) ) {
					continue;
				}
				$full = intdiv( $n, 8 );
				if ( substr( $a, 0, $full ) !== substr( $b, 0, $full ) ) {
					continue;
				}
				$rest = $n % 8;
				if ( 0 === $rest || ( ( ord( $a[ $full ] ) ^ ord( $b[ $full ] ) ) & ( 0xFF << ( 8 - $rest ) ) & 0xFF ) === 0 ) {
					return true;
				}
			}
		}
		return false;
	}

	public static function country_of_request() {
		return self::country();
	}

	private static function country() {
		foreach ( array( 'HTTP_CF_IPCOUNTRY', 'HTTP_CLOUDFRONT_VIEWER_COUNTRY', 'HTTP_X_APPENGINE_COUNTRY', 'HTTP_X_COUNTRY_CODE', 'GEOIP_COUNTRY_CODE', 'HTTP_X_VERCEL_IP_COUNTRY' ) as $k ) {
			if ( ! empty( $_SERVER[ $k ] ) && preg_match( '/^[A-Za-z]{2}$/', (string) $_SERVER[ $k ] ) && ! in_array( strtoupper( (string) $_SERVER[ $k ] ), array( 'XX', 'T1', 'ZZ' ), true ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				return strtoupper( (string) $_SERVER[ $k ] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			}
		}
		return '';
	}

	private static function normalize( $v ) {
		$v = (string) $v;
		if ( strlen( $v ) > self::MAX_VALUE ) {
			$v = substr( $v, 0, self::MAX_VALUE );
		}
		for ( $i = 0; $i < 2; $i++ ) {
			$d = rawurldecode( str_replace( '+', ' ', $v ) );
			if ( $d === $v ) {
				break;
			}
			$v = $d;
		}
		$v = str_replace( "\0", '', $v );
		$v = preg_replace( '#/\*!\d*#', ' ', $v ); // MySQL version comments: /*!50000union*/
		return preg_replace( '#/\*.*?\*/#s', ' ', $v ); // SQL comment tricks: UN/**/ION
	}

	private static function flatten( $arr, $prefix, array &$out, $depth = 0 ) {
		if ( $depth > 4 ) {
			return;
		}
		foreach ( (array) $arr as $k => $v ) {
			if ( count( $out ) >= self::MAX_VALUES ) {
				return;
			}
			$name = $prefix . ( '' === $prefix ? '' : '.' ) . ( is_int( $k ) ? '#' : substr( preg_replace( '/[^A-Za-z0-9_\-]/', '', (string) $k ), 0, 40 ) );
			if ( is_array( $v ) ) {
				self::flatten( $v, $name, $out, $depth + 1 );
			} else {
				$out[] = array( $name, (string) $v );
			}
		}
	}

	/** Request fields to inspect: list of array( target, name, value ). */
	private static function is_secret_field( $name ) {
		return (bool) preg_match( '/pass|pwd|card|cvv|cvc|iban|secret|token|nonce/i', (string) $name );
	}

	private static function fields( $logged_in_cookie ) {
		$f   = array();
		$raw = array();
		self::flatten( $_GET, '', $raw ); // phpcs:ignore WordPress.Security.NonceVerification
		foreach ( $raw as $r ) {
			$f[] = array( 'get', $r[0], $r[1] );
		}
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$f[] = array( 'uri', 'uri', $uri );
		// Bodies and cookies of signed-in users ( editors, shop managers ) legitimately contain code and markup: not inspected.
		if ( ! $logged_in_cookie ) {
			$raw = array();
			self::flatten( $_POST, '', $raw ); // phpcs:ignore WordPress.Security.NonceVerification
			foreach ( $raw as $r ) {
				if ( ! self::is_secret_field( $r[0] ) ) {
					$f[] = array( 'post', $r[0], $r[1] );
				}
			}
			$raw = array();
			self::flatten( $_COOKIE, '', $raw );
			foreach ( $raw as $r ) {
				if ( 0 !== strpos( $r[0], 'wordpress_' ) && 0 !== strpos( $r[0], 'wp-' ) ) {
					$f[] = array( 'cookie', 'cookie:' . $r[0], $r[1] );
				}
			}
		}
		return $f;
	}

	private static function has_login_cookie( $path = '' ) {
		// A cookie can be forged: it only relaxes the inspection of editors' bodies inside the admin area and the REST API.
		$base = strtolower( basename( (string) $path ) );
		if ( in_array( $base, array( 'admin-ajax.php', 'admin-post.php' ), true ) || ! preg_match( '#/(?:wp-admin|wp-json)(?:/|$)#i', (string) $path ) ) {
			return false;
		}
		foreach ( array_keys( $_COOKIE ) as $k ) {
			if ( 0 === strpos( (string) $k, 'wordpress_logged_in_' ) ) {
				return true;
			}
		}
		return false;
	}

	private static function request_id() {
		return substr( bin2hex( random_bytes( 4 ) ), 0, 8 );
	}

	/* ------------------------------------------------------------------ the check */

	/**
	 * Finds the first matching rule: array( rule id, class, field name, excerpt ) or null. Pure ( no I/O ), used by the tests too.
	 *
	 * @param array $req array( 'path' => '', 'ua' => '', 'fields' => [[target,name,value]], 'files' => string[], 'login' => bool )
	 */
	public static function match_request( array $req, array $skip_rules = array(), array $exceptions = array() ) {
		$rules  = self::rules();
		$path   = isset( $req['path'] ) ? strtolower( rawurldecode( (string) $req['path'] ) ) : '';
		$norm   = null; // normalised values, computed once
		$budget = self::MAX_BUDGET;
		foreach ( $rules as $cls => $list ) {
			foreach ( $list as $id => $def ) {
				if ( in_array( $id, $skip_rules, true ) || 'special' === $def[0] ) {
					continue;
				}
				list( $target, $re ) = $def;
				if ( 'path' === $target ) {
					if ( preg_match( $re, $path ) && ! in_array( $id . '|path', $exceptions, true ) ) {
						return array( $id, $cls, 'path', substr( $path, 0, 60 ) );
					}
					continue;
				}
				if ( 'ua' === $target ) {
					if ( ! empty( $req['ua'] ) && preg_match( $re, (string) $req['ua'] ) && ! in_array( $id . '|user-agent', $exceptions, true ) ) {
						return array( $id, $cls, 'user-agent', substr( (string) $req['ua'], 0, 60 ) );
					}
					continue;
				}
				if ( 'files' === $target ) {
					if ( empty( $req['login'] ) ) {
						foreach ( (array) ( isset( $req['files'] ) ? $req['files'] : array() ) as $fn ) {
							if ( preg_match( $re, (string) $fn ) && ! in_array( $id . '|file', $exceptions, true ) ) {
								return array( $id, $cls, 'file', substr( (string) $fn, 0, 60 ) );
							}
						}
					}
					continue;
				}
				if ( null === $norm ) {
					$norm = array();
					foreach ( (array) ( isset( $req['fields'] ) ? $req['fields'] : array() ) as $fld ) {
						list( $tg, $name, $value ) = $fld;
						if ( '' === $value || $budget <= 0 ) {
							continue;
						}
						$budget -= strlen( (string) $value );
						$norm[]  = array( $tg, $name, self::normalize( $value ) );
					}
				}
				foreach ( $norm as $fld ) {
					list( $tg, $name, $n ) = $fld;
					if ( 'values' === $target && 'uri' === $tg ) {
						continue;
					}
					if ( preg_match( $re, $n, $m ) && ! in_array( $id . '|' . $name, $exceptions, true ) ) {
						$ex = ( 'post' === $tg || 'cookie' === $tg ) ? '[hidden]' : substr( preg_replace( '/[^\x20-\x7e]/', '?', isset( $m[0] ) ? $m[0] : $n ), 0, 60 );
						return array( $id, $cls, $name, $ex );
					}
				}
			}
		}
		return null;
	}

	public static function boot() {
		if ( self::$booted ) {
			return;
		}
		self::$booted = true;
		if ( ( defined( 'WP_CLI' ) && WP_CLI ) || 'cli' === PHP_SAPI || ( defined( 'WP_INSTALLING' ) && WP_INSTALLING ) || empty( $_SERVER['REQUEST_METHOD'] ) ) {
			return;
		}
		if ( self::off_by_constant() ) {
			return;
		}
		try {
			self::inspect();
		} catch ( Throwable $e ) {
			// fail open
			return;
		}
	}

	private static function inspect() {
		$s = self::settings();
		if ( ! $s['enabled'] ) {
			return;
		}
		$rm = self::remote();
		if ( 'off' === $rm['switch'] ) {
			return;
		}
		$ip = self::client_ip();
		if ( self::ip_in( $ip, $s['allow_ips'] ) ) {
			return;
		}
		$uri  = isset( $_SERVER['REQUEST_URI'] ) ? (string) $_SERVER['REQUEST_URI'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$path = (string) parse_url( $uri, PHP_URL_PATH ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$base = strtolower( basename( $path ) );
		$is_login = (bool) preg_match( '#(?:^|/)wp-login\.php(?:/|$)#i', $path );
		$is_xml   = (bool) preg_match( '#(?:^|/)xmlrpc\.php(?:/|$)#i', $path );
		$admin_ck = $is_login || preg_match( '#/wp-admin(?:/|$)#i', $path ) ? self::has_login_cookie( '/wp-admin/' ) : false;
		$shared   = ! self::ip_is_public( $ip ); // behind a local proxy every visitor looks alike: no per-address rates

		// ---- special rules: IP, country, rates, XML-RPC
		$hit = null;
		if ( ! $admin_ck && self::ip_in( $ip, $s['block_ips'] ) && 'off' !== self::mode_of( 'ip', $s ) && ! in_array( 'ip_block', $rm['rules_off'], true ) ) {
			$hit = array( 'ip_block', 'ip', 'ip', 'listed address' );
		}
		if ( ! $hit && ! $admin_ck && ( $s['block_countries'] || $s['allow_countries'] ) && 'off' !== self::mode_of( 'ip', $s ) && ! in_array( 'country_block', $rm['rules_off'], true ) ) {
			$cc = self::country();
			if ( '' !== $cc ) {
				$block = array_filter( array_map( 'trim', preg_split( '/[\s,;]+/', strtoupper( (string) $s['block_countries'] ) ) ) );
				$allow = array_filter( array_map( 'trim', preg_split( '/[\s,;]+/', strtoupper( (string) $s['allow_countries'] ) ) ) );
				if ( ( $block && in_array( $cc, $block, true ) ) || ( $allow && ! in_array( $cc, $allow, true ) ) ) {
					$hit = array( 'country_block', 'ip', 'country', $cc );
				}
			}
		}
		$uid = (string) ( crc32( $ip ) % 4096 ); // few buckets: the number of counter rows stays small
		if ( ! $hit && ! $shared && $is_login && 'POST' === $_SERVER['REQUEST_METHOD'] && 'off' !== self::mode_of( 'rate', $s ) && ! in_array( 'rate_login', $rm['rules_off'], true ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			if ( Empedia_Cloud_Atomic::hit( 'fw:rl:' . $uid, 60 ) > 30 ) {
				$hit = array( 'rate_login', 'rate', 'wp-login.php', '>30 per minute' );
			}
		}
		if ( ! $hit && $is_xml ) {
			if ( ! $shared && 'off' !== self::mode_of( 'rate', $s ) && ! in_array( 'rate_xmlrpc', $rm['rules_off'], true ) && Empedia_Cloud_Atomic::hit( 'fw:rx:' . $uid, 60 ) > 40 ) {
				$hit = array( 'rate_xmlrpc', 'rate', 'xmlrpc.php', '>40 per minute' );
			}
			if ( ! $hit && 'off' !== self::mode_of( 'xmlrpc', $s ) && ! in_array( 'xmlrpc_multicall', $rm['rules_off'], true ) && 'POST' === $_SERVER['REQUEST_METHOD'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				$len = isset( $_SERVER['CONTENT_LENGTH'] ) ? (int) $_SERVER['CONTENT_LENGTH'] : 0; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				if ( $len > 0 && $len <= 1048576 ) {
					$body = (string) file_get_contents( 'php://input', false, null, 0, 262144 ); // phpcs:ignore WordPress.WP.AlternativeFunctions
					if ( false !== stripos( $body, 'system.multicall' ) && substr_count( strtolower( $body ), '<methodname>' ) > 20 ) {
						$hit = array( 'xmlrpc_multicall', 'xmlrpc', 'body', 'system.multicall > 20 calls' );
					}
				}
			}
		}

		// ---- pattern rules
		if ( ! $hit ) {
			$login  = self::has_login_cookie( $path );
			$files  = array();
			foreach ( $_FILES as $f ) { // phpcs:ignore WordPress.Security.NonceVerification
				$names = isset( $f['name'] ) ? $f['name'] : array();
				if ( is_array( $names ) ) {
					array_walk_recursive( $names, function ( $n ) use ( &$files ) {
						$files[] = (string) $n;
					} );
				} else {
					$files[] = (string) $names;
				}
			}
			$skip = $rm['rules_off'];
			foreach ( self::classes() as $c ) {
				if ( 'off' === self::mode_of( $c, $s ) ) {
					foreach ( self::rules()[ $c ] as $id => $def ) {
						$skip[] = $id;
					}
				}
			}
			$m = self::match_request(
				array( 'path' => $path, 'ua' => isset( $_SERVER['HTTP_USER_AGENT'] ) ? (string) $_SERVER['HTTP_USER_AGENT'] : '', 'fields' => self::fields( $login ), 'files' => $files, 'login' => $login ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
				$skip,
				$s['exceptions'] // marked as legitimate by the owner: the next match counts
			);
			$hit = $m;
		}
		if ( ! $hit ) {
			return;
		}
		self::handle( $hit, $s );
	}

	private static function handle( $hit, $s ) {
		list( $rule, $cls, $field, $excerpt ) = $hit;
		$mode  = self::mode_of( $cls, $s );
		$block = 'enforce' === $mode;
		$day   = gmdate( 'Y-m-d' );
		Empedia_Cloud_Atomic::count( self::CNT . $day . '_' . $rule . '_' . ( $block ? 'b' : 'o' ) );
		$id = self::request_id();
		// a few samples per rule and minute ( to judge false positives ); no addresses
		if ( Empedia_Cloud_Atomic::hit( 'fw:sample:' . $rule, 60 ) <= 5 ) {
			$smp   = get_option( self::SAMPLES, array() );
			$smp   = is_array( $smp ) ? $smp : array();
			$smp[] = array( 'id' => $id, 't' => time(), 'rule' => $rule, 'cls' => $cls, 'f' => $field, 'x' => $excerpt, 'b' => $block ? 1 : 0 );
			update_option( self::SAMPLES, array_slice( $smp, -40 ), false );
		}
		if ( ! $block ) {
			return;
		}
		// self protection: a class that blocks a lot in one minute pauses itself ( the rule is probably wrong )
		if ( Empedia_Cloud_Atomic::hit( 'fw:flood:' . $cls, 60 ) > 300 ) {
			set_transient( 'empedia_fw_pause_' . $cls, 1, 30 * MINUTE_IN_SECONDS );
			if ( class_exists( 'Empedia_Cloud_Watch' ) ) {
				Empedia_Cloud_Watch::record( 'firewall_paused', array( 'slug' => $cls ) );
			}
			return;
		}
		self::block( $id );
	}

	private static function block( $id ) {
		if ( ! headers_sent() ) {
			http_response_code( 403 );
			header( 'Content-Type: text/html; charset=utf-8' );
			header( 'Cache-Control: no-store' );
		}
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup; the only variable is escaped with htmlspecialchars (WordPress functions are not loaded this early).
		echo '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>403</title></head><body style="font-family:sans-serif;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>Request blocked</h1><p>The request looks like an attack and was blocked by the firewall of this site. If you think this is a mistake, please tell the site owner the reference below.</p><p>Reference: <code>' . htmlspecialchars( $id, ENT_QUOTES ) . '</code></p></body></html>';
		exit;
	}

	/* ------------------------------------------------------------------ statistics ( for the settings tab and the cloud ) */

	/** rule => array( observed, blocked ) of the last $days days */
	public static function stats( $days = 7 ) {
		$from = gmdate( 'Y-m-d', time() - ( $days - 1 ) * DAY_IN_SECONDS );
		$out  = array();
		foreach ( Empedia_Cloud_Atomic::counters( self::CNT ) as $name => $n ) {
			if ( preg_match( '/^' . self::CNT . '(\d{4}-\d{2}-\d{2})_([a-z_]+)_(o|b)$/', $name, $m ) && $m[1] >= $from ) {
				$out[ $m[2] ] = isset( $out[ $m[2] ] ) ? $out[ $m[2] ] : array( 0, 0 );
				$out[ $m[2] ][ 'o' === $m[3] ? 0 : 1 ] += $n;
			}
		}
		return $out;
	}

	public static function legit_counts() {
		$l = get_option( 'empedia_cloud_fw_legit', array() );
		return is_array( $l ) ? $l : array();
	}

	public static function samples() {
		$s = get_option( self::SAMPLES, array() );
		return is_array( $s ) ? array_reverse( $s ) : array();
	}

	/** The owner says that a sample was a legitimate request: this rule and field are not reported again. */
	public static function mark_legit( $sample_id ) {
		foreach ( self::samples() as $smp ) {
			if ( $smp['id'] === $sample_id ) {
				$s = self::settings();
				$k = $smp['rule'] . '|' . $smp['f'];
				if ( ! in_array( $k, $s['exceptions'], true ) && count( $s['exceptions'] ) < 200 ) {
					$s['exceptions'][] = $k;
					update_option( self::OPTION, $s, false );
				}
				$l = self::legit_counts();
				$l[ $smp['rule'] ] = ( isset( $l[ $smp['rule'] ] ) ? (int) $l[ $smp['rule'] ] : 0 ) + 1;
				update_option( 'empedia_cloud_fw_legit', $l, false );
				return true;
			}
		}
		return false;
	}

	/** Compact summary for the inventory. */
	public static function summary() {
		$s     = self::settings();
		$stats = self::stats( 7 );
		$legit = self::legit_counts();
		$rules = array();
		foreach ( self::rule_ids() as $id => $cls ) {
			if ( isset( $stats[ $id ] ) || isset( $legit[ $id ] ) ) {
				$rules[ $id ] = array( 'o' => isset( $stats[ $id ] ) ? $stats[ $id ][0] : 0, 'b' => isset( $stats[ $id ] ) ? $stats[ $id ][1] : 0, 'l' => isset( $legit[ $id ] ) ? (int) $legit[ $id ] : 0 );
			}
		}
		$modes = array();
		foreach ( self::classes() as $c ) {
			$modes[ $c ] = $s['modes'][ $c ];
		}
		return array(
			'enabled' => $s['enabled'] && ! self::off_by_constant(),
			'modes'   => $modes,
			'since'   => $s['since'],
			'rules'   => $rules,
			'paused'  => array_values( array_filter( self::classes(), function ( $c ) {
				return (bool) get_transient( 'empedia_fw_pause_' . $c );
			} ) ),
		);
	}

	public static function cleanup() {
		Empedia_Cloud_Atomic::purge_counters( self::CNT, gmdate( 'Y-m-d', time() - 14 * DAY_IN_SECONDS ) );
	}

	/* ------------------------------------------------------------------ must-use loader */

	/** File name of the loader before 1.7.0 ( plugin name EMPEDIAcloud ). */
	const MU_LEGACY = 'empedia-cloud-firewall.php';

	public static function mu_path() {
		return trailingslashit( WPMU_PLUGIN_DIR ) . 'empedia-shield-firewall.php';
	}

	public static function mu_installed() {
		return is_file( self::mu_path() );
	}

	/** An early loader from before 1.7.0 exists ( it points to the old plugin folder ). */
	public static function mu_legacy_installed() {
		return is_file( trailingslashit( WPMU_PLUGIN_DIR ) . self::MU_LEGACY );
	}

	/**
	 * Writes the early loader ( only on an explicit click ). The content is fixed apart from the path of this plugin; it only loads
	 * the two firewall files from the plugin folder and starts the firewall.
	 *
	 * @return bool False when the must-use folder cannot be created or written.
	 */
	/** A path as a single-quoted PHP string literal (for the generated loader file). */
	private static function php_string( $v ) {
		return "'" . addcslashes( (string) $v, "'\\" ) . "'";
	}

	public static function install_mu() {
		if ( ! is_dir( WPMU_PLUGIN_DIR ) && ! wp_mkdir_p( WPMU_PLUGIN_DIR ) ) {
			return false;
		}
		$dir = wp_normalize_path( dirname( __FILE__ ) );
		$php = "<?php\n/**\n * EMPEDIA Shield firewall loader ( generated by the plugin when you click \"Install early loader\" ).\n * It only loads the firewall of the plugin before other plugins. It is removed by the button \"Remove early loader\",\n * when the plugin is deactivated and when it is deleted.\n */\nif ( defined( 'ABSPATH' ) ) {\n\t\$f = " . self::php_string( $dir . '/class-empedia-firewall.php' ) . ";\n\t\$a = " . self::php_string( $dir . '/class-empedia-atomic.php' ) . ";\n\tif ( is_readable( \$f ) && is_readable( \$a ) ) {\n\t\trequire_once \$a;\n\t\trequire_once \$f;\n\t\tEmpedia_Cloud_Firewall::boot();\n\t}\n}\n";
		$ok  = false !== @file_put_contents( self::mu_path(), $php ); // phpcs:ignore WordPress.WP.AlternativeFunctions, WordPress.PHP.NoSilencedErrors
		if ( $ok && self::mu_legacy_installed() ) {
			@unlink( trailingslashit( WPMU_PLUGIN_DIR ) . self::MU_LEGACY ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
		}
		return $ok;
	}

	/** Removes the early loader ( and a loader of an earlier version ). */
	public static function remove_mu() {
		foreach ( array( self::mu_path(), trailingslashit( WPMU_PLUGIN_DIR ) . self::MU_LEGACY ) as $file ) {
			if ( is_file( $file ) ) {
				@unlink( $file ); // phpcs:ignore WordPress.PHP.NoSilencedErrors, WordPress.WP.AlternativeFunctions
			}
		}
	}
}

} // class_exists
