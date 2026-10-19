<?php
/**
 * Storage targets that connect through EMPEDIAcloud with a login: Google Drive, Microsoft OneDrive, Dropbox, Box and pCloud.
 *
 * The customer connects their OWN account. The app credentials ( client ID and secret ) belong to the operator and exist only in the cloud:
 * this plugin never has a client secret. Connecting: begin() asks the cloud for the address of the login page, the browser comes back
 * with ?empedia_oauth=<state> and claim() fetches the tokens ( exactly once ). Tokens are kept encrypted in the target settings; an expired
 * access token is renewed through the cloud ( /backup/oauth/refresh ) because only the cloud can exchange it.
 *
 * Backups lie in  <folder>/<backup id>/<file>  below an app folder or an own folder ( “EMPEDIAcloud Backups” ). The plugin never reads
 * or deletes anything outside of that folder. API calls go to fixed https hosts of the providers; redirects of downloads are followed by hand
 * and the access token is only sent to the hosts of the provider API.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Empedia_Cloud_Target_Oauth extends Empedia_Cloud_Target {

	const DEFAULT_FOLDER = 'EMPEDIAcloud Backups';

	/** @var string Provider id ( key of Empedia_Cloud_Targets::oauth_types() ). */
	protected $type = '';

	/** Provider API hosts ( name => origin ). @return array */
	abstract protected function default_hosts();

	/* ------------------------------------------------------------- registry */

	/** @return Empedia_Cloud_Target_Oauth|null */
	public static function make( $type, $tid, array $cfg ) {
		$map = array(
			'gdrive'   => 'Empedia_Cloud_Target_Gdrive',
			'onedrive' => 'Empedia_Cloud_Target_Onedrive',
			'dropbox'  => 'Empedia_Cloud_Target_Dropbox',
			'box'      => 'Empedia_Cloud_Target_Box',
			'pcloud'   => 'Empedia_Cloud_Target_Pcloud',
		);
		if ( ! isset( $map[ $type ] ) ) {
			return null;
		}
		return new $map[ $type ]( $tid, $cfg );
	}

	/* ------------------------------------------------------------ connecting */

	/**
	 * Asks the cloud for the address of the provider login page.
	 *
	 * @param string $type       Provider id.
	 * @param string $return_url Address in wp-admin the browser returns to ( with ?empedia_oauth=<state> or ?empedia_oauth_error=<code> ).
	 * @return string|WP_Error
	 */
	public static function begin( $type, $return_url ) {
		if ( ! isset( Empedia_Cloud_Targets::oauth_types()[ $type ] ) ) {
			return new WP_Error( 'oauth_type', 'type' );
		}
		$r = Empedia_Cloud_Client::request( 'POST', '/backup/oauth/start', array( 'provider' => $type, 'return_url' => $return_url ), true, 30 );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return ( ! empty( $r['auth_url'] ) && is_string( $r['auth_url'] ) ) ? $r['auth_url'] : new WP_Error( 'oauth_start', 'start' );
	}

	/**
	 * Fetches the tokens after the login ( works once per state ).
	 *
	 * @param string $state Value of ?empedia_oauth.
	 * @return array|WP_Error Array( 'type', 'label', 'cfg' ) for Empedia_Cloud_Targets::save().
	 */
	public static function claim( $state ) {
		$state = (string) $state;
		if ( ! preg_match( '/^[A-Za-z0-9_-]{43}$/', $state ) ) {
			return new WP_Error( 'oauth_state', 'state' );
		}
		$r = Empedia_Cloud_Client::request( 'POST', '/backup/oauth/claim', array( 'state' => $state ), true, 30 );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$types = Empedia_Cloud_Targets::oauth_types();
		if ( empty( $r['provider'] ) || ! isset( $types[ $r['provider'] ] ) || empty( $r['access_token'] ) ) {
			return new WP_Error( 'oauth_claim', 'claim' );
		}
		$account = isset( $r['account'] ) ? sanitize_text_field( (string) $r['account'] ) : '';
		$cfg     = array(
			'access_token'  => (string) $r['access_token'],
			'refresh_token' => isset( $r['refresh_token'] ) ? (string) $r['refresh_token'] : '',
			'expires_at'    => ! empty( $r['expires_in'] ) ? time() + (int) $r['expires_in'] : 0,
			'account'       => $account,
			'path'          => self::DEFAULT_FOLDER,
		);
		if ( ! empty( $r['api_host'] ) && is_string( $r['api_host'] ) && preg_match( '/^[a-z0-9.-]{3,80}$/i', $r['api_host'] ) ) {
			$cfg['api_host'] = strtolower( $r['api_host'] );
		}
		return array(
			'type'  => $r['provider'],
			'label' => $types[ $r['provider'] ] . ( '' !== $account ? ' – ' . $account : '' ),
			'cfg'   => $cfg,
		);
	}

	/** Human readable text for the error codes of this class ( for the settings page ). */
	public static function error_text( $code ) {
		$map = array(
			'reauth_required' => __( 'The connection was revoked or expired. Please connect the account again.', 'empedia-shield' ),
			'oauth_quota'     => __( 'The storage of your account is full.', 'empedia-shield' ),
			'oauth_auth'      => __( 'The provider denied access. Please connect the account again.', 'empedia-shield' ),
		);
		return isset( $map[ $code ] ) ? $map[ $code ] : __( 'The storage provider returned an error.', 'empedia-shield' );
	}

	/* ------------------------------------------------------------------ setup */

	public function __construct( $tid, array $cfg ) {
		parent::__construct( $tid, $cfg );
		foreach ( Empedia_Cloud_Targets::oauth_types() as $id => $label ) {
			unset( $label );
			if ( 'Empedia_Cloud_Target_' . ucfirst( $id ) === get_class( $this ) ) {
				$this->type = $id;
			}
		}
	}

	public function part_size() {
		return 8388608;
	}

	/** Folder prefix; defaults to the own folder of the plugin. */
	protected function base() {
		$b = trim( (string) $this->opt( 'path', '' ), '/' );
		return '' === $b ? self::DEFAULT_FOLDER : $b;
	}

	/** API origins ( filterable for tests ). @return array */
	protected function hosts() {
		return (array) apply_filters( 'empedia_cloud_oauth_hosts', $this->default_hosts(), $this->type, $this->cfg );
	}

	protected function host( $name = 'api' ) {
		$h = $this->hosts();
		return rtrim( isset( $h[ $name ] ) ? $h[ $name ] : reset( $h ), '/' );
	}

	/** Path segments of a path below the target ( unencoded ). */
	protected function segs( $path ) {
		return array_values( array_filter( explode( '/', trim( (string) $path, '/' ) ), 'strlen' ) );
	}

	/** Name of an object level ( no slashes ). */
	protected static function leaf( $name ) {
		return basename( str_replace( '\\', '/', (string) $name ) );
	}

	/* ----------------------------------------------------------------- tokens */

	/** @return string|WP_Error Valid access token. */
	protected function token() {
		$exp = (int) $this->opt( 'expires_at', 0 );
		if ( '' !== (string) $this->opt( 'refresh_token', '' ) && $exp && $exp - 90 < time() ) {
			$r = $this->refresh( (string) $this->opt( 'access_token', '' ) );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
		}
		$t = (string) $this->opt( 'access_token', '' );
		return '' === $t ? new WP_Error( 'reauth_required', 'reauth' ) : $t;
	}

	/**
	 * Renews the access token through the cloud and saves it.
	 *
	 * @param string $failed Access token that was just used ( another process may have renewed it already ).
	 * @return true|WP_Error
	 */
	protected function refresh( $failed ) {
		$fresh = Empedia_Cloud_Targets::instance( $this->tid );
		if ( $fresh instanceof self && '' !== (string) $fresh->opt( 'access_token', '' ) && (string) $fresh->opt( 'access_token', '' ) !== $failed ) {
			$this->cfg = $fresh->cfg; // renewed by a parallel step: use it ( refresh tokens of some providers work only once )
			return true;
		}
		$rt = (string) $this->opt( 'refresh_token', '' );
		if ( '' === $rt ) {
			return $this->reauth();
		}
		$r = Empedia_Cloud_Client::request( 'POST', '/backup/oauth/refresh', array( 'provider' => $this->type, 'refresh_token' => $rt ), true, 30 );
		if ( is_wp_error( $r ) ) {
			if ( 'empedia_reauth_required' === $r->get_error_code() ) {
				return $this->reauth();
			}
			return new WP_Error( 'oauth_refresh', $r->get_error_message() );
		}
		if ( empty( $r['access_token'] ) ) {
			return new WP_Error( 'oauth_refresh', 'refresh' );
		}
		$ch = array(
			'access_token' => (string) $r['access_token'],
			'expires_at'   => ! empty( $r['expires_in'] ) ? time() + (int) $r['expires_in'] : 0,
		);
		if ( ! empty( $r['refresh_token'] ) ) {
			$ch['refresh_token'] = (string) $r['refresh_token'];
		}
		Empedia_Cloud_Targets::update_cfg( $this->tid, $ch );
		$this->cfg = array_merge( $this->cfg, $ch );
		return true;
	}

	protected function reauth() {
		Empedia_Cloud_Targets::mark( $this->tid, 'reauth_required' );
		return new WP_Error( 'reauth_required', 'reauth' );
	}

	/* ------------------------------------------------------------------- http */

	/**
	 * One API call with the access token ( renewed once on 401, one retry on 429/503 ).
	 *
	 * @return array|WP_Error array( code, body, headers ).
	 */
	protected function call( $method, $url, array $args = array(), $auth = true ) {
		$args += array(
			'method'      => $method,
			'timeout'     => 90,
			'redirection' => 0,
			'headers'     => array(),
		);
		$tried = false;
		$slept = false;
		for ( $i = 0; $i < 4; $i++ ) {
			if ( $auth ) {
				$tok = $this->token();
				if ( is_wp_error( $tok ) ) {
					return $tok;
				}
				$args['headers']['Authorization'] = 'Bearer ' . $tok;
			}
			$res = wp_remote_request( $url, $args );
			if ( is_wp_error( $res ) ) {
				return new WP_Error( 'oauth_http', 'connection failed' );
			}
			$code = (int) wp_remote_retrieve_response_code( $res );
			if ( 401 === $code && $auth && ! $tried ) {
				$tried = true;
				$r     = $this->refresh( $tok );
				if ( is_wp_error( $r ) ) {
					return $r;
				}
				continue;
			}
			if ( ( 429 === $code || 503 === $code ) && ! $slept ) {
				$slept = true;
				$wait  = (int) wp_remote_retrieve_header( $res, 'retry-after' );
				sleep( max( 1, min( 5, $wait ) ) );
				continue;
			}
			return array(
				'code'    => $code,
				'body'    => (string) wp_remote_retrieve_body( $res ),
				'headers' => $res['headers'],
			);
		}
		return new WP_Error( 'oauth_http', 'connection failed' );
	}

	/** Error of a failed call. */
	protected static function fail( array $r ) {
		$b = strtolower( substr( $r['body'], 0, 2000 ) );
		if ( 507 === $r['code'] || false !== strpos( $b, 'insufficient_space' ) || false !== strpos( $b, 'storagequotaexceeded' ) || false !== strpos( $b, 'quotalimitreached' ) || false !== strpos( $b, 'storage_limit_exceeded' ) ) {
			return new WP_Error( 'oauth_quota', 'quota' );
		}
		if ( 401 === $r['code'] ) {
			return new WP_Error( 'reauth_required', 'reauth' );
		}
		if ( 403 === $r['code'] ) {
			return new WP_Error( 'oauth_auth', 'access denied' );
		}
		if ( 404 === $r['code'] || ( 409 === $r['code'] && false !== strpos( $b, 'not_found' ) ) ) { // Dropbox answers 409 path/not_found
			return new WP_Error( 'oauth_notfound', 'not found' );
		}
		return new WP_Error( 'oauth_' . $r['code'], 'http ' . $r['code'] );
	}

	protected static function ok( array $r ) {
		return $r['code'] >= 200 && $r['code'] < 300;
	}

	protected static function json( array $r ) {
		$j = json_decode( $r['body'], true );
		return is_array( $j ) ? $j : array();
	}

	/** Is this redirect target one of the API hosts ( the token may go there )? */
	private function is_api_host( $url ) {
		$h = wp_parse_url( $url, PHP_URL_HOST );
		foreach ( $this->hosts() as $o ) {
			if ( wp_parse_url( $o, PHP_URL_HOST ) === $h ) {
				return true;
			}
		}
		return false;
	}

	/** May a download be fetched from this address ( https, or the scheme of the API in tests )? */
	protected function download_ok( $url ) {
		$s = wp_parse_url( $url, PHP_URL_SCHEME );
		$a = wp_parse_url( $this->host(), PHP_URL_SCHEME );
		return 'https' === $s || ( 'http' === $s && 'http' === $a );
	}

	/**
	 * Fetches an object ( following redirects by hand; the token only goes to the API hosts ).
	 *
	 * @param string      $dest Local file to append to ( null: return the body ).
	 * @return string|true|WP_Error
	 */
	protected function fetch( $method, $url, array $args = array(), $dest = null, $auth = true ) {
		$tmp = null === $dest ? trailingslashit( get_temp_dir() ) . 'empedia-' . strtolower( wp_generate_password( 12, false, false ) ) . '.dl' : $dest . '.dl';
		for ( $hop = 0; $hop < 4; $hop++ ) {
			$with_auth = $auth && ( 0 === $hop || $this->is_api_host( $url ) );
			$a         = $args + array( 'stream' => true, 'filename' => $tmp );
			if ( ! $with_auth ) {
				$r = wp_remote_request( $url, $a + array( 'method' => $method, 'timeout' => 120, 'redirection' => 0 ) );
				if ( is_wp_error( $r ) ) {
					wp_delete_file( $tmp );
					return new WP_Error( 'oauth_http', 'connection failed' );
				}
				$r = array( 'code' => (int) wp_remote_retrieve_response_code( $r ), 'body' => '', 'headers' => $r['headers'] );
			} else {
				$r = $this->call( $method, $url, $a, true );
				if ( is_wp_error( $r ) ) {
					wp_delete_file( $tmp );
					return $r;
				}
			}
			if ( $r['code'] >= 300 && $r['code'] < 400 ) {
				$loc = isset( $r['headers']['location'] ) ? (string) $r['headers']['location'] : '';
				if ( '' === $loc || ! $this->download_ok( $loc ) ) {
					wp_delete_file( $tmp );
					return new WP_Error( 'oauth_redirect', 'redirect' );
				}
				$url    = $loc;
				$method = 'GET';
				$args   = array( 'headers' => array() );
				continue;
			}
			if ( 200 !== $r['code'] ) {
				$body = is_file( $tmp ) ? (string) file_get_contents( $tmp, false, null, 0, 2000 ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions
				wp_delete_file( $tmp );
				$r['body'] = $body;
				return self::fail( $r );
			}
			if ( null === $dest ) {
				$data = (string) file_get_contents( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				wp_delete_file( $tmp );
				return $data;
			}
			$in  = fopen( $tmp, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			$out = fopen( $dest, 'ab' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( ! $in || ! $out ) {
				return new WP_Error( 'write', 'write' );
			}
			stream_copy_to_stream( $in, $out );
			fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			wp_delete_file( $tmp );
			return true;
		}
		wp_delete_file( $tmp );
		return new WP_Error( 'oauth_redirect', 'too many redirects' );
	}

	public function get( $rel ) {
		return $this->read( $rel, null );
	}

	public function get_to( $rel, $dest ) {
		return $this->read( $rel, $dest );
	}

	/** Reads an object as a string ( $dest null ) or appends it to a file. @return string|true|WP_Error */
	abstract protected function read( $rel, $dest );

	/** Multipart body ( parts: [ [ headers, content ] ] ) and its content type. @return array [ type, body ] */
	protected static function multipart( array $parts, $subtype ) {
		$b    = 'empedia' . bin2hex( random_bytes( 12 ) );
		$body = '';
		foreach ( $parts as $p ) {
			$body .= '--' . $b . "\r\n" . $p[0] . "\r\n\r\n" . $p[1] . "\r\n";
		}
		return array( 'multipart/' . $subtype . '; boundary=' . $b, $body . '--' . $b . "--\r\n" );
	}
}

/* ====================================================================== Google Drive */

class Empedia_Cloud_Target_Gdrive extends Empedia_Cloud_Target_Oauth {

	const FOLDER = 'application/vnd.google-apps.folder';

	/** @var array Folder ids of this run ( path => id ). */
	private $ids = array();

	public function part_size() {
		return 5242880; // one multipart request per part
	}

	protected function default_hosts() {
		return array( 'api' => 'https://www.googleapis.com' );
	}

	private static function q( $s ) {
		return "'" . str_replace( array( '\\', "'" ), array( '\\\\', "\\'" ), $s ) . "'";
	}

	/** Lists files of a query. @return array|WP_Error rows ( id, name ). */
	private function search( $query ) {
		$out  = array();
		$page = '';
		do {
			$url = $this->host() . '/drive/v3/files?' . http_build_query(
				array(
					'q'        => $query,
					'fields'   => 'nextPageToken,files(id,name)',
					'pageSize' => 1000,
					'spaces'   => 'drive',
					'orderBy'  => 'createdTime',
				) + ( '' !== $page ? array( 'pageToken' => $page ) : array() )
			);
			$r   = $this->call( 'GET', $url );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( ! self::ok( $r ) ) {
				return self::fail( $r );
			}
			$j    = self::json( $r );
			$out  = array_merge( $out, isset( $j['files'] ) ? (array) $j['files'] : array() );
			$page = isset( $j['nextPageToken'] ) ? (string) $j['nextPageToken'] : '';
		} while ( '' !== $page && count( $out ) < 20000 );
		return $out;
	}

	/** Id of the folder at $segs ( created when $create ), null when missing. @return string|null|WP_Error */
	private function folder( array $segs, $create ) {
		$parent = 'root';
		$path   = '';
		foreach ( $segs as $seg ) {
			$path .= '/' . $seg;
			if ( isset( $this->ids[ $path ] ) ) {
				$parent = $this->ids[ $path ];
				continue;
			}
			$rows = $this->search( 'name = ' . self::q( $seg ) . ' and ' . self::q( $parent ) . ' in parents and mimeType = ' . self::q( self::FOLDER ) . ' and trashed = false' );
			if ( is_wp_error( $rows ) ) {
				return $rows;
			}
			if ( $rows ) {
				$id = (string) $rows[0]['id'];
			} elseif ( $create ) {
				$r = $this->call(
					'POST',
					$this->host() . '/drive/v3/files?fields=id',
					array(
						'headers' => array( 'Content-Type' => 'application/json' ),
						'body'    => wp_json_encode( array( 'name' => $seg, 'mimeType' => self::FOLDER, 'parents' => array( $parent ) ) ),
					)
				);
				if ( is_wp_error( $r ) ) {
					return $r;
				}
				$j = self::json( $r );
				if ( ! self::ok( $r ) || empty( $j['id'] ) ) {
					return self::fail( $r );
				}
				$id = (string) $j['id'];
			} else {
				return null;
			}
			$this->ids[ $path ] = $id;
			$parent             = $id;
		}
		return $parent;
	}

	/** Splits a relative object path into the folder id and the file name. @return array|WP_Error|null */
	private function locate( $rel, $create ) {
		$segs = $this->segs( $this->full( $rel ) );
		$name = array_pop( $segs );
		$dir  = $this->folder( $segs, $create );
		if ( is_wp_error( $dir ) ) {
			return $dir;
		}
		return null === $dir ? null : array( $dir, $name );
	}

	private function file_id( $dir, $name ) {
		$rows = $this->search( 'name = ' . self::q( $name ) . ' and ' . self::q( $dir ) . ' in parents and mimeType != ' . self::q( self::FOLDER ) . ' and trashed = false' );
		if ( is_wp_error( $rows ) ) {
			return $rows;
		}
		return $rows ? (string) $rows[0]['id'] : null;
	}

	public function put( $rel, $data ) {
		$loc = $this->locate( $rel, true );
		if ( is_wp_error( $loc ) ) {
			return $loc;
		}
		list( $dir, $name ) = $loc;
		$id = $this->file_id( $dir, $name );
		if ( is_wp_error( $id ) ) {
			return $id;
		}
		if ( $id ) { // replace content in place ( no duplicate names )
			$r = $this->call( 'PATCH', $this->host() . '/upload/drive/v3/files/' . rawurlencode( $id ) . '?uploadType=media&fields=id', array( 'headers' => array( 'Content-Type' => 'application/octet-stream' ), 'body' => (string) $data ) );
		} else {
			list( $type, $body ) = self::multipart(
				array(
					array( 'Content-Type: application/json; charset=UTF-8', wp_json_encode( array( 'name' => $name, 'parents' => array( $dir ) ) ) ),
					array( 'Content-Type: application/octet-stream', (string) $data ),
				),
				'related'
			);
			$r = $this->call( 'POST', $this->host() . '/upload/drive/v3/files?uploadType=multipart&fields=id', array( 'headers' => array( 'Content-Type' => $type ), 'body' => $body ) );
		}
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return self::ok( $r ) ? true : self::fail( $r );
	}

	protected function read( $rel, $dest ) {
		$loc = $this->locate( $rel, false );
		if ( is_wp_error( $loc ) ) {
			return $loc;
		}
		if ( ! $loc ) {
			return new WP_Error( 'oauth_notfound', 'not found' );
		}
		$id = $this->file_id( $loc[0], $loc[1] );
		if ( is_wp_error( $id ) ) {
			return $id;
		}
		if ( ! $id ) {
			return new WP_Error( 'oauth_notfound', 'not found' );
		}
		return $this->fetch( 'GET', $this->host() . '/drive/v3/files/' . rawurlencode( $id ) . '?alt=media', array(), $dest );
	}

	public function dirs() {
		$base = $this->folder( $this->segs( $this->base() ), false );
		if ( is_wp_error( $base ) ) {
			return $base;
		}
		if ( null === $base ) {
			return array();
		}
		$rows = $this->search( self::q( $base ) . ' in parents and mimeType = ' . self::q( self::FOLDER ) . ' and trashed = false' );
		return is_wp_error( $rows ) ? $rows : array_values( array_unique( array_map( 'strval', wp_list_pluck( $rows, 'name' ) ) ) );
	}

	public function remove( $name ) {
		$name = self::leaf( $name );
		$base = $this->folder( $this->segs( $this->base() ), false );
		if ( is_wp_error( $base ) ) {
			return $base;
		}
		if ( null === $base || '' === $name ) {
			return true;
		}
		$rows = $this->search( 'name = ' . self::q( $name ) . ' and ' . self::q( $base ) . ' in parents and mimeType = ' . self::q( self::FOLDER ) . ' and trashed = false' );
		if ( is_wp_error( $rows ) ) {
			return $rows;
		}
		foreach ( $rows as $row ) {
			$r = $this->call( 'DELETE', $this->host() . '/drive/v3/files/' . rawurlencode( (string) $row['id'] ) );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( ! self::ok( $r ) && 404 !== $r['code'] ) {
				return self::fail( $r );
			}
		}
		unset( $this->ids[ '/' . implode( '/', $this->segs( $this->base() ) ) . '/' . $name ] );
		return true;
	}

	public function close() {
		$this->ids = array();
	}
}

/* ================================================================== Microsoft OneDrive */

class Empedia_Cloud_Target_Onedrive extends Empedia_Cloud_Target_Oauth {

	public function part_size() {
		return 3145728; // simple upload works up to 4 MB
	}

	protected function default_hosts() {
		return array( 'api' => 'https://graph.microsoft.com/v1.0' );
	}

	/** URL of an item below the app folder ( path based ); $suffix like ':/content' or ':/children'. */
	private function item( $rel, $suffix = '' ) {
		$segs = $this->segs( $this->full( $rel ) );
		$root = $this->host() . '/me/drive/special/approot';
		if ( ! $segs ) {
			return $root . ( '' === $suffix ? '' : str_replace( ':', '', $suffix ) );
		}
		return $root . ':/' . implode( '/', array_map( 'rawurlencode', $segs ) ) . ( '' === $suffix ? '' : $suffix );
	}

	public function put( $rel, $data ) {
		$r = $this->call( 'PUT', $this->item( $rel, ':/content' ), array( 'headers' => array( 'Content-Type' => 'application/octet-stream' ), 'body' => (string) $data ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return self::ok( $r ) ? true : self::fail( $r );
	}

	protected function read( $rel, $dest ) {
		return $this->fetch( 'GET', $this->item( $rel, ':/content' ), array(), $dest );
	}

	public function dirs() {
		$url = $this->item( '', ':/children' ) . ( false === strpos( $this->item( '', ':/children' ), '?' ) ? '?' : '&' ) . '$select=name,folder&$top=200';
		$out = array();
		for ( $i = 0; $i < 200 && $url; $i++ ) {
			$r = $this->call( 'GET', $url );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( 404 === $r['code'] ) {
				return array();
			}
			if ( ! self::ok( $r ) ) {
				return self::fail( $r );
			}
			$j = self::json( $r );
			foreach ( isset( $j['value'] ) ? (array) $j['value'] : array() as $v ) {
				if ( isset( $v['folder'], $v['name'] ) ) {
					$out[] = (string) $v['name'];
				}
			}
			$next = isset( $j['@odata.nextLink'] ) ? (string) $j['@odata.nextLink'] : '';
			$url  = ( '' !== $next && wp_parse_url( $next, PHP_URL_HOST ) === wp_parse_url( $this->host(), PHP_URL_HOST ) ) ? $next : '';
		}
		return $out;
	}

	public function remove( $name ) {
		$name = self::leaf( $name );
		if ( '' === $name ) {
			return true;
		}
		$r = $this->call( 'DELETE', $this->item( $name, ':' ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return ( self::ok( $r ) || 404 === $r['code'] ) ? true : self::fail( $r );
	}
}

/* ========================================================================== Dropbox */

class Empedia_Cloud_Target_Dropbox extends Empedia_Cloud_Target_Oauth {

	protected function default_hosts() {
		return array(
			'api'     => 'https://api.dropboxapi.com',
			'content' => 'https://content.dropboxapi.com',
		);
	}

	private function path( $rel ) {
		return '/' . implode( '/', $this->segs( $this->full( $rel ) ) );
	}

	/** JSON call to the API host. @return array|WP_Error */
	private function rpc( $endpoint, array $body ) {
		return $this->call( 'POST', $this->host( 'api' ) . $endpoint, array( 'headers' => array( 'Content-Type' => 'application/json' ), 'body' => wp_json_encode( $body ) ) );
	}

	private static function not_found( array $r ) {
		return 409 === $r['code'] && false !== strpos( $r['body'], 'not_found' );
	}

	public function put( $rel, $data ) {
		$r = $this->call(
			'POST',
			$this->host( 'content' ) . '/2/files/upload',
			array(
				'headers' => array(
					'Content-Type'    => 'application/octet-stream',
					'Dropbox-API-Arg' => wp_json_encode( array( 'path' => $this->path( $rel ), 'mode' => 'overwrite', 'autorename' => false, 'mute' => true ) ),
				),
				'body'    => (string) $data,
			)
		);
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return self::ok( $r ) ? true : self::fail( $r );
	}

	protected function read( $rel, $dest ) {
		return $this->fetch( 'POST', $this->host( 'content' ) . '/2/files/download', array( 'headers' => array( 'Dropbox-API-Arg' => wp_json_encode( array( 'path' => $this->path( $rel ) ) ) ) ), $dest );
	}

	public function dirs() {
		$base = $this->segs( $this->base() );
		$path = $base ? '/' . implode( '/', $base ) : '';
		$out  = array();
		$r    = $this->rpc( '/2/files/list_folder', array( 'path' => $path, 'limit' => 2000 ) );
		for ( $i = 0; $i < 200; $i++ ) {
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( self::not_found( $r ) ) {
				return array();
			}
			if ( ! self::ok( $r ) ) {
				return self::fail( $r );
			}
			$j = self::json( $r );
			foreach ( isset( $j['entries'] ) ? (array) $j['entries'] : array() as $e ) {
				if ( isset( $e['.tag'], $e['name'] ) && 'folder' === $e['.tag'] ) {
					$out[] = (string) $e['name'];
				}
			}
			if ( empty( $j['has_more'] ) || empty( $j['cursor'] ) ) {
				break;
			}
			$r = $this->rpc( '/2/files/list_folder/continue', array( 'cursor' => (string) $j['cursor'] ) );
		}
		return $out;
	}

	public function remove( $name ) {
		$name = self::leaf( $name );
		if ( '' === $name ) {
			return true;
		}
		$r = $this->rpc( '/2/files/delete_v2', array( 'path' => $this->path( $name ) ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return ( self::ok( $r ) || self::not_found( $r ) ) ? true : self::fail( $r );
	}
}

/* ============================================================================== Box */

class Empedia_Cloud_Target_Box extends Empedia_Cloud_Target_Oauth {

	/** @var array Folder ids of this run ( path => id ). */
	private $ids = array();

	protected function default_hosts() {
		return array(
			'api'    => 'https://api.box.com/2.0',
			'upload' => 'https://upload.box.com/api/2.0',
		);
	}

	/** Items of a folder. @return array|WP_Error rows ( id, name, type ). */
	private function items( $folder ) {
		$out = array();
		for ( $off = 0; $off < 100000; ) {
			$r = $this->call( 'GET', $this->host() . '/folders/' . rawurlencode( $folder ) . '/items?' . http_build_query( array( 'fields' => 'id,name,type', 'limit' => 1000, 'offset' => $off ) ) );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			if ( ! self::ok( $r ) ) {
				return self::fail( $r );
			}
			$j    = self::json( $r );
			$rows = isset( $j['entries'] ) ? (array) $j['entries'] : array();
			$out  = array_merge( $out, $rows );
			$off += count( $rows );
			if ( ! $rows || $off >= (int) ( isset( $j['total_count'] ) ? $j['total_count'] : 0 ) ) {
				break;
			}
		}
		return $out;
	}

	private static function find( array $rows, $name, $type ) {
		foreach ( $rows as $row ) {
			if ( isset( $row['name'], $row['type'], $row['id'] ) && (string) $row['name'] === $name && $type === $row['type'] ) {
				return (string) $row['id'];
			}
		}
		return null;
	}

	/** @return string|null|WP_Error */
	private function folder( array $segs, $create ) {
		$parent = '0';
		$path   = '';
		foreach ( $segs as $seg ) {
			$path .= '/' . $seg;
			if ( isset( $this->ids[ $path ] ) ) {
				$parent = $this->ids[ $path ];
				continue;
			}
			$rows = $this->items( $parent );
			if ( is_wp_error( $rows ) ) {
				return $rows;
			}
			$id = self::find( $rows, $seg, 'folder' );
			if ( null === $id ) {
				if ( ! $create ) {
					return null;
				}
				$r = $this->call( 'POST', $this->host() . '/folders', array( 'headers' => array( 'Content-Type' => 'application/json' ), 'body' => wp_json_encode( array( 'name' => $seg, 'parent' => array( 'id' => $parent ) ) ) ) );
				if ( is_wp_error( $r ) ) {
					return $r;
				}
				$j = self::json( $r );
				if ( 409 === $r['code'] ) { // created meanwhile
					$c  = isset( $j['context_info']['conflicts'] ) ? $j['context_info']['conflicts'] : array();
					$id = isset( $c['id'] ) ? (string) $c['id'] : ( isset( $c[0]['id'] ) ? (string) $c[0]['id'] : null );
				} elseif ( self::ok( $r ) && ! empty( $j['id'] ) ) {
					$id = (string) $j['id'];
				}
				if ( null === $id ) {
					return self::fail( $r );
				}
			}
			$this->ids[ $path ] = $id;
			$parent             = $id;
		}
		return $parent;
	}

	private function locate( $rel, $create ) {
		$segs = $this->segs( $this->full( $rel ) );
		$name = array_pop( $segs );
		$dir  = $this->folder( $segs, $create );
		if ( is_wp_error( $dir ) ) {
			return $dir;
		}
		return null === $dir ? null : array( $dir, $name );
	}

	private function upload( $url, array $attrs, $name, $data ) {
		list( $type, $body ) = self::multipart(
			array(
				array( 'Content-Disposition: form-data; name="attributes"', wp_json_encode( $attrs ) ),
				array( 'Content-Disposition: form-data; name="file"; filename="' . str_replace( '"', '', $name ) . '"' . "\r\n" . 'Content-Type: application/octet-stream', (string) $data ),
			),
			'form-data'
		);
		return $this->call( 'POST', $url, array( 'headers' => array( 'Content-Type' => $type ), 'body' => $body ) );
	}

	public function put( $rel, $data ) {
		$loc = $this->locate( $rel, true );
		if ( is_wp_error( $loc ) ) {
			return $loc;
		}
		list( $dir, $name ) = $loc;
		$r = $this->upload( $this->host( 'upload' ) . '/files/content', array( 'name' => $name, 'parent' => array( 'id' => $dir ) ), $name, $data );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( 409 === $r['code'] ) { // already there ( retry of a part ): upload a new version
			$j  = self::json( $r );
			$c  = isset( $j['context_info']['conflicts'] ) ? $j['context_info']['conflicts'] : array();
			$id = isset( $c['id'] ) ? (string) $c['id'] : ( isset( $c[0]['id'] ) ? (string) $c[0]['id'] : '' );
			if ( '' === $id ) {
				return self::fail( $r );
			}
			$r = $this->upload( $this->host( 'upload' ) . '/files/' . rawurlencode( $id ) . '/content', array( 'name' => $name ), $name, $data );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
		}
		return self::ok( $r ) ? true : self::fail( $r );
	}

	protected function read( $rel, $dest ) {
		$loc = $this->locate( $rel, false );
		if ( is_wp_error( $loc ) ) {
			return $loc;
		}
		if ( ! $loc ) {
			return new WP_Error( 'oauth_notfound', 'not found' );
		}
		$rows = $this->items( $loc[0] );
		if ( is_wp_error( $rows ) ) {
			return $rows;
		}
		$id = self::find( $rows, $loc[1], 'file' );
		if ( null === $id ) {
			return new WP_Error( 'oauth_notfound', 'not found' );
		}
		return $this->fetch( 'GET', $this->host() . '/files/' . rawurlencode( $id ) . '/content', array(), $dest );
	}

	public function dirs() {
		$base = $this->folder( $this->segs( $this->base() ), false );
		if ( is_wp_error( $base ) ) {
			return $base;
		}
		if ( null === $base ) {
			return array();
		}
		$rows = $this->items( $base );
		if ( is_wp_error( $rows ) ) {
			return $rows;
		}
		$out = array();
		foreach ( $rows as $row ) {
			if ( isset( $row['type'], $row['name'] ) && 'folder' === $row['type'] ) {
				$out[] = (string) $row['name'];
			}
		}
		return $out;
	}

	public function remove( $name ) {
		$name = self::leaf( $name );
		$base = $this->folder( $this->segs( $this->base() ), false );
		if ( is_wp_error( $base ) ) {
			return $base;
		}
		if ( null === $base || '' === $name ) {
			return true;
		}
		$rows = $this->items( $base );
		if ( is_wp_error( $rows ) ) {
			return $rows;
		}
		$id = self::find( $rows, $name, 'folder' );
		if ( null === $id ) {
			return true;
		}
		$r = $this->call( 'DELETE', $this->host() . '/folders/' . rawurlencode( $id ) . '?recursive=true' );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( ! self::ok( $r ) && 404 !== $r['code'] ) {
			return self::fail( $r );
		}
		$this->call( 'DELETE', $this->host() . '/folders/' . rawurlencode( $id ) . '/trash' ); // best effort: free the space right away
		unset( $this->ids[ '/' . implode( '/', $this->segs( $this->base() ) ) . '/' . $name ] );
		return true;
	}

	public function close() {
		$this->ids = array();
	}
}

/* ========================================================================== pCloud */

class Empedia_Cloud_Target_Pcloud extends Empedia_Cloud_Target_Oauth {

	/** @var array Folders known to exist ( path => true ). */
	private $made = array();

	protected function default_hosts() {
		$h = strtolower( (string) $this->opt( 'api_host', 'eapi.pcloud.com' ) );
		if ( ! in_array( $h, array( 'eapi.pcloud.com', 'api.pcloud.com' ), true ) ) {
			$h = 'eapi.pcloud.com';
		}
		return array( 'api' => 'https://' . $h );
	}

	/** Result codes that mean “log in again”. */
	private static function auth_result( $n ) {
		return in_array( (int) $n, array( 1000, 2000, 2094, 2095 ), true );
	}

	/**
	 * Calls a pCloud method. @return array|WP_Error decoded answer with result 0.
	 *
	 * @param int[] $allow Result codes that are not errors ( for example 2005: folder does not exist ).
	 */
	private function api( $method, array $params, $body = null, array $allow = array() ) {
		$args = array( 'headers' => array() );
		if ( null !== $body ) {
			$args['body']                    = $body;
			$args['headers']['Content-Type'] = 'application/octet-stream';
			$args['method']                  = 'POST';
		}
		$r = $this->call( null === $body ? 'GET' : 'POST', $this->host() . '/' . $method . '?' . http_build_query( $params ), $args );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$j = self::json( $r );
		if ( ! isset( $j['result'] ) ) {
			return self::fail( $r );
		}
		$n = (int) $j['result'];
		if ( 0 === $n || in_array( $n, $allow, true ) ) {
			return $j;
		}
		if ( self::auth_result( $n ) ) {
			return $this->reauth();
		}
		if ( 2008 === $n ) {
			return new WP_Error( 'oauth_quota', 'quota' );
		}
		return new WP_Error( 'oauth_pcloud_' . $n, 'pcloud ' . $n );
	}

	private function path( $rel ) {
		return '/' . implode( '/', $this->segs( $this->full( $rel ) ) );
	}

	/** Creates $dir level by level. @return true|WP_Error */
	private function mkdirs( $dir ) {
		$cur = '';
		foreach ( $this->segs( $dir ) as $seg ) {
			$cur .= '/' . $seg;
			if ( isset( $this->made[ $cur ] ) ) {
				continue;
			}
			$r = $this->api( 'createfolderifnotexists', array( 'path' => $cur ) );
			if ( is_wp_error( $r ) ) {
				return $r;
			}
			$this->made[ $cur ] = true;
		}
		return true;
	}

	public function put( $rel, $data ) {
		$path = $this->path( $rel );
		$dir  = dirname( $path );
		$m    = $this->mkdirs( $dir );
		if ( is_wp_error( $m ) ) {
			return $m;
		}
		$r = $this->api( 'uploadfile', array( 'path' => $dir, 'filename' => basename( $path ), 'nopartial' => 1 ), (string) $data );
		return is_wp_error( $r ) ? $r : true;
	}

	protected function read( $rel, $dest ) {
		$r = $this->api( 'getfilelink', array( 'path' => $this->path( $rel ) ), null, array( 2009 ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		if ( empty( $r['hosts'][0] ) || empty( $r['path'] ) ) {
			return new WP_Error( 'oauth_notfound', 'not found' );
		}
		$host = (string) $r['hosts'][0];
		$api  = (string) wp_parse_url( $this->host(), PHP_URL_HOST ) . ( wp_parse_url( $this->host(), PHP_URL_PORT ) ? ':' . wp_parse_url( $this->host(), PHP_URL_PORT ) : '' );
		$same = ( $host === $api ); // tests: the stub serves downloads itself
		if ( ! $same && ! preg_match( '/^[a-z0-9-]+(\.[a-z0-9-]+)*\.pcloud\.(com|link)$/i', $host ) ) {
			return new WP_Error( 'oauth_redirect', 'host' );
		}
		$scheme = wp_parse_url( $this->host(), PHP_URL_SCHEME );
		return $this->fetch( 'GET', $scheme . '://' . $host . $r['path'], array( 'headers' => array() ), $dest, false );
	}

	public function dirs() {
		$r = $this->api( 'listfolder', array( 'path' => $this->path( '' ), 'nofiles' => 1 ), null, array( 2005 ) );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$out = array();
		foreach ( isset( $r['metadata']['contents'] ) ? (array) $r['metadata']['contents'] : array() as $c ) {
			if ( ! empty( $c['isfolder'] ) && isset( $c['name'] ) ) {
				$out[] = (string) $c['name'];
			}
		}
		return $out;
	}

	public function remove( $name ) {
		$name = self::leaf( $name );
		if ( '' === $name ) {
			return true;
		}
		$r = $this->api( 'deletefolderrecursive', array( 'path' => $this->path( $name ) ), null, array( 2005 ) );
		unset( $this->made[ $this->path( $name ) ] );
		return is_wp_error( $r ) ? $r : true;
	}

	public function close() {
		$this->made = array();
	}
}
