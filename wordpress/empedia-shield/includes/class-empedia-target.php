<?php
/**
 * Storage targets for backups: base class and registry.
 *
 * A target stores objects below  <backup id>/<name>  ( encrypted parts and a manifest ). Every target implements the
 * same small set of calls, so uploading, listing, restoring and pruning work the same for all of them.
 * Settings of a target ( passwords, tokens ) are kept encrypted with a key derived from the WordPress salts.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

abstract class Empedia_Cloud_Target {

	/** @var array Decrypted settings. */
	protected $cfg = array();
	/** @var string Id of this target ( key in the registry ). */
	protected $tid = '';

	public function __construct( $tid, array $cfg ) {
		$this->tid = $tid;
		$this->cfg = $cfg;
	}

	public function tid() {
		return $this->tid;
	}

	/** Size of one uploaded part ( bytes ). */
	public function part_size() {
		return 8388608;
	}

	/** @return true|WP_Error */
	abstract public function put( $rel, $data );

	/** @return string|WP_Error */
	abstract public function get( $rel );

	/** Appends the object to the local file $dest. @return true|WP_Error */
	public function get_to( $rel, $dest ) {
		$d = $this->get( $rel );
		if ( is_wp_error( $d ) ) {
			return $d;
		}
		return false === file_put_contents( $dest, $d, FILE_APPEND ) ? new WP_Error( 'write', 'write' ) : true; // phpcs:ignore WordPress.WP.AlternativeFunctions
	}

	/** Names of the backup folders at the top level. @return string[]|WP_Error */
	abstract public function dirs();

	/** Deletes a backup folder with everything in it. @return true|WP_Error */
	abstract public function remove( $name );

	/** Writes, reads and deletes a small file. @return true|WP_Error */
	public function test() {
		$rel = 'empedia-test-' . wp_generate_password( 6, false, false ) . '/probe.txt';
		$r   = $this->put( $rel, 'ok' );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$g = $this->get( $rel );
		$this->remove( dirname( $rel ) );
		return ( ! is_wp_error( $g ) && 'ok' === $g ) ? true : new WP_Error( 'verify', 'verify' );
	}

	/** Uploads bytes of a file as one object. @return true|WP_Error */
	public function put_part( $rel, $file, $offset, $len ) {
		$fh = fopen( $file, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $fh ) {
			return new WP_Error( 'read', 'read' );
		}
		fseek( $fh, $offset );
		$data = fread( $fh, $len ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( strlen( (string) $data ) !== $len ) {
			return new WP_Error( 'read', 'read' );
		}
		return $this->put( $rel, $data );
	}

	/** Called when a run is over ( close connections ). */
	public function close() {}

	/** Setting with a default. */
	protected function opt( $k, $d = '' ) {
		return isset( $this->cfg[ $k ] ) && '' !== $this->cfg[ $k ] ? $this->cfg[ $k ] : $d;
	}

	/** Folder prefix inside the target without slashes at the ends ( '' = top level ). */
	protected function base() {
		return trim( (string) $this->opt( 'path', '' ), '/' );
	}

	protected function full( $rel ) {
		$b = $this->base();
		return ( '' === $b ? '' : $b . '/' ) . ltrim( $rel, '/' );
	}
}

/**
 * Registry of the configured targets ( encrypted settings in one option ).
 */
class Empedia_Cloud_Targets {

	const OPTION = 'empedia_backup_targets';

	/**
	 * Types that can be added: the built-in ones plus those registered by add-on plugins.
	 *
	 * Extension point for add-on plugins: filter 'empedia_shield_backup_target_types'. Add an entry per type:
	 *
	 *     add_filter( 'empedia_shield_backup_target_types', function ( $types ) {
	 *         $types['sftp'] = array(
	 *             'label'  => 'SFTP (SSH)',                 // shown in the list and the form
	 *             'class'  => 'My_Sftp_Target',             // subclass of Empedia_Cloud_Target, already loaded when the filter runs
	 *             'fields' => array(                        // form fields: name => [ label, type text|password|textarea|checkbox, required, help ]
	 *                 'host' => array( 'label' => 'Server', 'type' => 'text', 'required' => true ),
	 *                 ...
	 *             ),
	 *         );
	 *         return $types;
	 *     } );
	 *
	 * The class implements put(), get(), dirs(), remove() ( and optionally get_to(), put_part(), part_size(), close() ), see the
	 * base class above. Fields named password, secret or private_key are kept when left empty in the edit form. The instance
	 * is created with new $class( $target_id, $settings ); to build it differently, use the filter
	 * 'empedia_shield_backup_target_instance' ( null, $type, $target_id, $settings ). Built-in types cannot be replaced.
	 *
	 * Settings of a target are stored by type: when the add-on is missing, the saved target stays ( see addon_types() ).
	 */
	public static function types() {
		return array_merge( self::builtin_types(), self::extension_types() );
	}

	/** Types registered by add-on plugins ( validated ). */
	private static function extension_types() {
		$ext   = apply_filters( 'empedia_shield_backup_target_types', array() );
		$built = self::builtin_types();
		$out   = array();
		foreach ( is_array( $ext ) ? $ext : array() as $k => $d ) {
			$k = is_string( $k ) ? sanitize_key( $k ) : '';
			if ( '' === $k || isset( $built[ $k ] ) || isset( self::oauth_types()[ $k ] ) || ! is_array( $d ) ) {
				continue;
			}
			if ( empty( $d['label'] ) || ! is_string( $d['label'] ) || empty( $d['class'] ) || ! is_string( $d['class'] ) || empty( $d['fields'] ) || ! is_array( $d['fields'] ) ) {
				continue;
			}
			$fields = array();
			foreach ( $d['fields'] as $fk => $f ) {
				if ( is_string( $fk ) && is_array( $f ) && ! empty( $f['label'] ) ) {
					$fields[ $fk ] = array_merge( array( 'type' => 'text', 'required' => false ), $f );
				}
			}
			if ( $fields ) {
				$out[ $k ] = array( 'label' => $d['label'], 'class' => $d['class'], 'fields' => $fields, 'addon' => true );
			}
		}
		return $out;
	}

	/** Types that are provided by an add-on plugin: type => [ label, addon ]. Used to explain saved targets while the add-on is missing. */
	public static function addon_types() {
		return array(
			'sftp' => array( 'label' => 'SFTP (SSH)', 'addon' => 'EMPEDIA Shield SFTP' ),
		);
	}

	/** Is a saved target waiting for an add-on that is not active? */
	public static function needs_addon( $type ) {
		$a = self::addon_types();
		return isset( $a[ $type ] ) && ! isset( self::types()[ $type ] );
	}

	private static function builtin_types() {
		$path = array( 'label' => __( 'Folder', 'empedia-shield' ), 'type' => 'text', 'required' => false, 'help' => __( 'Folder for the backups, for example empedia-backups. It is created if needed.', 'empedia-shield' ) );
		return array(
			's3'     => array(
				'label'  => __( 'S3-compatible storage', 'empedia-shield' ),
				'class'  => 'Empedia_Cloud_Target_S3',
				'file'   => 's3',
				'fields' => array(
					// phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent -- only an example address in a help text, nothing is loaded from it.
					'endpoint' => array( 'label' => __( 'Endpoint', 'empedia-shield' ), 'type' => 'text', 'required' => true, 'help' => __( 'For example https://s3.eu-central-1.amazonaws.com or the address of your provider.', 'empedia-shield' ) ),
					'region'   => array( 'label' => __( 'Region', 'empedia-shield' ), 'type' => 'text', 'required' => false, 'help' => __( 'For example eu-central-1. Many providers accept the default.', 'empedia-shield' ) ),
					'bucket'   => array( 'label' => __( 'Bucket', 'empedia-shield' ), 'type' => 'text', 'required' => true ),
					'key'      => array( 'label' => __( 'Access key', 'empedia-shield' ), 'type' => 'text', 'required' => true ),
					'secret'   => array( 'label' => __( 'Secret key', 'empedia-shield' ), 'type' => 'password', 'required' => true ),
					'path'     => $path,
				),
			),
			'webdav' => array(
				'label'  => __( 'WebDAV (Nextcloud, ownCloud, …)', 'empedia-shield' ),
				'class'  => 'Empedia_Cloud_Target_Webdav',
				'file'   => 'webdav',
				'fields' => array(
					'url'      => array( 'label' => __( 'WebDAV address', 'empedia-shield' ), 'type' => 'text', 'required' => true, 'help' => __( 'For Nextcloud: https://cloud.example.com/remote.php/dav/files/USER', 'empedia-shield' ) ),
					'user'     => array( 'label' => __( 'User', 'empedia-shield' ), 'type' => 'text', 'required' => true ),
					'password' => array( 'label' => __( 'Password', 'empedia-shield' ), 'type' => 'password', 'required' => true, 'help' => __( 'Use an app password if your service offers one.', 'empedia-shield' ) ),
					'path'     => $path,
				),
			),
			'ftp'    => array(
				'label'  => __( 'FTP / FTPS', 'empedia-shield' ),
				'class'  => 'Empedia_Cloud_Target_Ftp',
				'file'   => 'ftp',
				'fields' => array(
					'host'     => array( 'label' => __( 'Server', 'empedia-shield' ), 'type' => 'text', 'required' => true ),
					'port'     => array( 'label' => __( 'Port', 'empedia-shield' ), 'type' => 'text', 'required' => false, 'help' => __( 'Default 21.', 'empedia-shield' ) ),
					'user'     => array( 'label' => __( 'User', 'empedia-shield' ), 'type' => 'text', 'required' => true ),
					'password' => array( 'label' => __( 'Password', 'empedia-shield' ), 'type' => 'password', 'required' => true ),
					'tls'      => array( 'label' => __( 'Encrypt the connection (FTPS)', 'empedia-shield' ), 'type' => 'checkbox', 'required' => false, 'help' => __( 'Strongly recommended. Plain FTP sends the password unencrypted.', 'empedia-shield' ) ),
					'path'     => $path,
				),
			),
		);
	}

	/** Types that connect through EMPEDIAcloud ( OAuth ); see class-empedia-target-oauth.php. */
	public static function oauth_types() {
		return array(
			'gdrive'   => 'Google Drive',
			'onedrive' => 'Microsoft OneDrive',
			'dropbox'  => 'Dropbox',
			'box'      => 'Box',
			'pcloud'   => 'pCloud',
		);
	}

	/* ------------------------------------------------------------------ storage */

	private static function key() {
		return hash_hkdf( 'sha256', wp_salt( 'auth' ) . wp_salt( 'secure_auth' ), 32, 'empedia-cloud-targets' );
	}

	private static function seal( array $cfg ) {
		$n = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
		return base64_encode( $n . sodium_crypto_secretbox( wp_json_encode( $cfg ), $n, self::key() ) );
	}

	private static function unseal( $b64 ) {
		$raw = base64_decode( (string) $b64, true );
		if ( ! $raw || strlen( $raw ) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
			return null;
		}
		$p = sodium_crypto_secretbox_open( substr( $raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), substr( $raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ), self::key() );
		$j = false === $p ? null : json_decode( $p, true );
		return is_array( $j ) ? $j : null;
	}

	/** Configured targets without secrets: id => [ type, label, enabled, ok ]. */
	public static function listing() {
		$o = get_option( self::OPTION, array() );
		$o = is_array( $o ) ? $o : array();
		$out = array();
		foreach ( $o as $id => $t ) {
			$out[ $id ] = array(
				'type'    => isset( $t['type'] ) ? $t['type'] : '',
				'label'   => isset( $t['label'] ) ? $t['label'] : $id,
				'enabled' => ! empty( $t['enabled'] ),
				'ok'      => null !== self::unseal( isset( $t['cfg'] ) ? $t['cfg'] : '' ),
				'tested'  => isset( $t['tested'] ) ? (int) $t['tested'] : 0,
				'error'   => isset( $t['error'] ) ? (string) $t['error'] : '',
			);
		}
		return $out;
	}

	/** Adds or replaces a target. @return string id */
	public static function save( $id, $type, $label, array $cfg, $enabled = true ) {
		$o = get_option( self::OPTION, array() );
		$o = is_array( $o ) ? $o : array();
		if ( ! $id ) {
			$id = $type . '-' . strtolower( wp_generate_password( 6, false, false ) );
		}
		$old       = isset( $o[ $id ] ) ? self::unseal( $o[ $id ]['cfg'] ) : null;
		foreach ( (array) $old as $k => $v ) {
			if ( ( ! isset( $cfg[ $k ] ) || '' === $cfg[ $k ] ) && in_array( $k, array( 'password', 'secret', 'private_key', 'access_token', 'refresh_token' ), true ) ) {
				$cfg[ $k ] = $v; // an empty password field keeps the saved secret
			}
		}
		$o[ $id ] = array(
			'type'    => $type,
			'label'   => $label,
			'enabled' => (bool) $enabled,
			'cfg'     => self::seal( $cfg ),
			'tested'  => 0,
			'error'   => '',
		);
		update_option( self::OPTION, $o, false );
		return $id;
	}

	/** Updates settings of a target ( for example a refreshed OAuth token ). */
	public static function update_cfg( $id, array $changes ) {
		$o = get_option( self::OPTION, array() );
		if ( ! is_array( $o ) || ! isset( $o[ $id ] ) ) {
			return;
		}
		$cfg = self::unseal( $o[ $id ]['cfg'] );
		if ( null === $cfg ) {
			return;
		}
		$o[ $id ]['cfg'] = self::seal( array_merge( $cfg, $changes ) );
		update_option( self::OPTION, $o, false );
	}

	public static function mark( $id, $error ) {
		$o = get_option( self::OPTION, array() );
		if ( is_array( $o ) && isset( $o[ $id ] ) ) {
			$o[ $id ]['tested'] = time();
			$o[ $id ]['error']  = (string) $error;
			update_option( self::OPTION, $o, false );
		}
	}

	public static function set_enabled( $id, $on ) {
		$o = get_option( self::OPTION, array() );
		if ( is_array( $o ) && isset( $o[ $id ] ) ) {
			$o[ $id ]['enabled'] = (bool) $on;
			update_option( self::OPTION, $o, false );
		}
	}

	public static function remove( $id ) {
		$o = get_option( self::OPTION, array() );
		if ( is_array( $o ) && isset( $o[ $id ] ) ) {
			unset( $o[ $id ] );
			update_option( self::OPTION, $o, false );
		}
	}

	/** Settings of a target for the edit form ( secrets replaced by an empty value ). */
	public static function form_values( $id ) {
		$o = get_option( self::OPTION, array() );
		if ( ! is_array( $o ) || ! isset( $o[ $id ] ) ) {
			return null;
		}
		$cfg = self::unseal( $o[ $id ]['cfg'] );
		if ( null === $cfg ) {
			return null;
		}
		foreach ( array( 'password', 'secret', 'private_key', 'access_token', 'refresh_token' ) as $k ) {
			unset( $cfg[ $k ] );
		}
		return array( 'type' => $o[ $id ]['type'], 'label' => $o[ $id ]['label'], 'cfg' => $cfg );
	}

	/** Instance of a configured target or null ( unreadable settings, unknown type ). */
	public static function instance( $id ) {
		$o = get_option( self::OPTION, array() );
		if ( ! is_array( $o ) || ! isset( $o[ $id ] ) ) {
			return null;
		}
		$cfg = self::unseal( $o[ $id ]['cfg'] );
		if ( null === $cfg ) {
			return null;
		}
		$type  = $o[ $id ]['type'];
		$types = self::types();
		if ( isset( $types[ $type ] ) ) {
			if ( ! empty( $types[ $type ]['addon'] ) ) {
				// Add-on type: the add-on may build the instance itself, otherwise the registered class is used.
				$custom = apply_filters( 'empedia_shield_backup_target_instance', null, $type, $id, $cfg );
				if ( $custom instanceof Empedia_Cloud_Target ) {
					return $custom;
				}
				$cls = $types[ $type ]['class'];
				return class_exists( $cls ) && is_subclass_of( $cls, 'Empedia_Cloud_Target' ) ? new $cls( $id, $cfg ) : null;
			}
			$file = EMPEDIA_CLOUD_DIR . 'includes/targets/class-empedia-target-' . $types[ $type ]['file'] . '.php';
			if ( ! class_exists( $types[ $type ]['class'], false ) && is_file( $file ) ) {
				require_once $file;
			}
			return class_exists( $types[ $type ]['class'], false ) ? new $types[ $type ]['class']( $id, $cfg ) : null;
		}
		if ( isset( self::oauth_types()[ $type ] ) ) {
			$file = EMPEDIA_CLOUD_DIR . 'includes/targets/class-empedia-target-oauth.php';
			if ( ! class_exists( 'Empedia_Cloud_Target_Oauth', false ) && is_file( $file ) ) {
				require_once $file;
			}
			return class_exists( 'Empedia_Cloud_Target_Oauth', false ) ? Empedia_Cloud_Target_Oauth::make( $type, $id, $cfg ) : null;
		}
		return null;
	}

	/** All enabled targets of this site ( the EMPEDIAcloud storage first ). @return Empedia_Cloud_Target[] */
	public static function active() {
		$out = array();
		if ( Empedia_Cloud_Bunny::enabled() ) {
			$out['cloud'] = new Empedia_Cloud_Target_Bunny( 'cloud', array() );
		}
		foreach ( self::listing() as $id => $t ) {
			if ( $t['enabled'] && $t['ok'] ) {
				$i = self::instance( $id );
				if ( $i ) {
					$out[ $id ] = $i;
				}
			}
		}
		return $out;
	}

	/** One target by id ( 'cloud' = EMPEDIAcloud storage ). */
	public static function get( $id ) {
		if ( 'cloud' === $id ) {
			return Empedia_Cloud_Bunny::has_zone() ? new Empedia_Cloud_Target_Bunny( 'cloud', array() ) : null;
		}
		return self::instance( $id );
	}

	public static function label_of( $id ) {
		if ( 'cloud' === $id ) {
			return __( 'EMPEDIAcloud storage', 'empedia-shield' );
		}
		$l = self::listing();
		return isset( $l[ $id ] ) ? $l[ $id ]['label'] : $id;
	}

	/* ----------------------------------------------------------- backups in a target */

	/** Backups in a target ( from their manifests ), newest first. @return array|WP_Error */
	public static function backups( Empedia_Cloud_Target $t, $force = false ) {
		$key = 'empedia_tl_' . substr( md5( $t->tid() ), 0, 12 );
		if ( ! $force ) {
			$c = get_transient( $key );
			if ( is_array( $c ) ) {
				return $c;
			}
		}
		$dirs = $t->dirs();
		if ( is_wp_error( $dirs ) ) {
			return $dirs;
		}
		$out = array();
		foreach ( $dirs as $d ) {
			if ( ! preg_match( '/^[A-Za-z0-9\-]{10,40}$/', $d ) ) {
				continue;
			}
			$m = $t->get( $d . '/manifest.json' );
			$j = is_wp_error( $m ) ? null : json_decode( $m, true );
			if ( is_array( $j ) && ! empty( $j['id'] ) && $j['id'] === $d && ! empty( $j['parts'] ) ) {
				$out[] = $j;
			}
		}
		usort(
			$out,
			static function ( $a, $b ) {
				return strcmp( (string) $b['created'], (string) $a['created'] );
			}
		);
		set_transient( $key, $out, 120 );
		return $out;
	}

	public static function forget_listing( $tid ) {
		delete_transient( 'empedia_tl_' . substr( md5( $tid ), 0, 12 ) );
	}

	/** Deletes the oldest backups beyond $keep. */
	public static function prune( Empedia_Cloud_Target $t, $keep ) {
		$l = self::backups( $t, true );
		if ( is_wp_error( $l ) ) {
			return;
		}
		foreach ( array_slice( $l, max( 1, (int) $keep ) ) as $old ) {
			$t->remove( $old['id'] );
		}
		self::forget_listing( $t->tid() );
	}

	/** Manifest of a finished upload ( written last, so a missing manifest means “incomplete” ). */
	public static function manifest( array $s, $parts, $part_size ) {
		$m = isset( $s['manifest'] ) ? $s['manifest'] : array();
		return array(
			'v'         => 1,
			'id'        => $s['id'],
			'created'   => gmdate( 'c' ),
			'file'      => $s['file'],
			'size'      => (int) $s['up']['size'],
			'sha256'    => $s['up']['sha'],
			'parts'     => (int) $parts,
			'part_size' => (int) $part_size,
			'encrypted' => true,
			'scope'     => $s['scope'],
			'site_url'  => isset( $m['site_url'] ) ? $m['site_url'] : site_url(),
			'wp'        => isset( $m['wp'] ) ? $m['wp'] : '',
			'files'     => isset( $m['files'] ) ? (int) $m['files'] : 0,
		);
	}
}
