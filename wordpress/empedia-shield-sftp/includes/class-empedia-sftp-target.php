<?php
/**
 * Storage target: SFTP ( SSH ), provided by the add-on plugin EMPEDIA Shield SFTP.
 * Registered in EMPEDIA Shield through the filter 'empedia_shield_backup_target_types'.
 *
 * Two engines: the PHP extension "ssh2" ( fast, password login, fingerprints as SHA1/MD5 ) or the bundled phpseclib 3
 * in this add-on's lib/ ( private keys, SHA256 fingerprints ). The engine is picked automatically; the filter
 * "empedia_shield_sftp_engine" can force 'ssh2' or 'seclib'.
 *
 * Host key: when a fingerprint is saved it must match, otherwise the connection is refused ( sftp_hostkey ).
 * When it is empty, the fingerprint of the first successful connection is remembered ( trust on first use ).
 *
 * @package EmpediaShieldSftp
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Target_Sftp extends Empedia_Cloud_Target {

	/** @var string '' | 'ssh2' | 'seclib' */
	private $eng = '';
	/** @var resource|\phpseclib3\Net\SFTP|null ssh2 session resource or phpseclib SFTP object */
	private $ssh = null;
	/** @var resource|null ssh2 SFTP subsystem */
	private $sftp = null;
	/** @var string ssh2: home folder of the user ( the stream wrapper needs absolute paths ) */
	private $home = '';
	/** @var array Folders known to exist. */
	private $made = array();

	/* ------------------------------------------------------------ fingerprints */

	/** Saved fingerprint in a normal form: [ kind sha256|sha1|md5, value ] or null. */
	private static function fp_parse( $fp ) {
		$fp = trim( (string) $fp );
		if ( '' === $fp ) {
			return null;
		}
		if ( 0 === stripos( $fp, 'SHA256:' ) ) {
			return array( 'sha256', rtrim( substr( $fp, 7 ), '=' ) );
		}
		$h = strtolower( preg_replace( '/^(sha1|md5):/i', '', $fp ) );
		$h = str_replace( ':', '', $h );
		if ( preg_match( '/^[0-9a-f]{40}$/', $h ) ) {
			return array( 'sha1', $h );
		}
		if ( preg_match( '/^[0-9a-f]{32}$/', $h ) ) {
			return array( 'md5', $h );
		}
		if ( preg_match( '/^[A-Za-z0-9+\/]{43}=?$/', $fp ) ) { // bare SHA256 in base64
			return array( 'sha256', rtrim( $fp, '=' ) );
		}
		return false;
	}

	/** Fingerprint of a host key blob in the saved form $kind. */
	private static function fp_of_blob( $blob, $kind ) {
		if ( 'sha256' === $kind ) {
			return rtrim( base64_encode( hash( 'sha256', $blob, true ) ), '=' );
		}
		return hash( $kind, $blob );
	}

	private function remember( $fp ) {
		if ( '' === (string) $this->opt( 'fingerprint', '' ) && '' !== $this->tid && class_exists( 'Empedia_Cloud_Targets', false ) ) {
			$this->cfg['fingerprint'] = $fp;
			Empedia_Cloud_Targets::update_cfg( $this->tid, array( 'fingerprint' => $fp ) );
		}
	}

	/* ----------------------------------------------------------------- engine */

	private function seclib_ready() {
		$f = EMPEDIA_SHIELD_SFTP_DIR . 'lib/autoload.php';
		if ( ! is_file( $f ) || ! is_file( EMPEDIA_SHIELD_SFTP_DIR . 'lib/phpseclib/Net/SFTP.php' ) ) {
			return false;
		}
		require_once $f;
		return class_exists( '\phpseclib3\Net\SFTP' );
	}

	/** @return string|WP_Error */
	private function pick_engine() {
		$want = apply_filters( 'empedia_shield_sftp_engine', 'auto' );
		$fp   = self::fp_parse( $this->opt( 'fingerprint', '' ) );
		if ( false === $fp ) {
			return new WP_Error( 'sftp_fingerprint', 'fingerprint format' );
		}
		$has_key = '' !== trim( (string) $this->opt( 'private_key', '' ) );
		$ssh2_ok = function_exists( 'ssh2_connect' ) && ! $has_key && ! preg_match( '/[?#%]/', (string) $this->opt( 'path', '' ) ) && ( ! $fp || 'sha256' !== $fp[0] );
		if ( 'ssh2' === $want ) {
			return function_exists( 'ssh2_connect' ) ? 'ssh2' : new WP_Error( 'sftp_missing', 'ssh2 missing' );
		}
		if ( 'seclib' === $want || ! $ssh2_ok ) {
			return $this->seclib_ready() ? 'seclib' : new WP_Error( 'sftp_missing', 'library missing' );
		}
		return 'ssh2';
	}

	/** @return true|WP_Error */
	private function connect() {
		if ( $this->ssh ) {
			return true;
		}
		$host = (string) $this->opt( 'host', '' );
		$port = (int) $this->opt( 'port', 22 );
		$user = (string) $this->opt( 'user', '' );
		if ( '' === $host || '' === $user || $port < 1 || $port > 65535 ) {
			return new WP_Error( 'sftp_config', 'config' );
		}
		$eng = $this->pick_engine();
		if ( is_wp_error( $eng ) ) {
			return $eng;
		}
		$this->made = array();
		try {
			$r = 'ssh2' === $eng ? $this->connect_ssh2( $host, $port, $user ) : $this->connect_seclib( $host, $port, $user );
		} catch ( \Throwable $e ) {
			$r = new WP_Error( 'sftp_connect', 'connection failed' );
		}
		if ( is_wp_error( $r ) ) {
			$this->close();
			return $r;
		}
		$this->eng = $eng;
		return true;
	}

	private function connect_ssh2( $host, $port, $user ) {
		$c = @ssh2_connect( $host, $port ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $c ) {
			return new WP_Error( 'sftp_connect', 'connection failed' );
		}
		$fp  = self::fp_parse( $this->opt( 'fingerprint', '' ) );
		$got = strtolower( (string) @ssh2_fingerprint( $c, SSH2_FINGERPRINT_SHA1 | SSH2_FINGERPRINT_HEX ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( $fp ) {
			$md5 = 'md5' === $fp[0] ? strtolower( (string) @ssh2_fingerprint( $c, SSH2_FINGERPRINT_MD5 | SSH2_FINGERPRINT_HEX ) ) : ''; // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( ! hash_equals( $fp[1], 'md5' === $fp[0] ? $md5 : $got ) ) {
				return new WP_Error( 'sftp_hostkey', 'host key changed' );
			}
		}
		if ( '' === (string) $this->opt( 'password', '' ) || ! @ssh2_auth_password( $c, $user, (string) $this->opt( 'password' ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new WP_Error( 'sftp_login', 'login failed' );
		}
		$s = @ssh2_sftp( $c ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $s ) {
			return new WP_Error( 'sftp_subsystem', 'sftp not available' );
		}
		$home = @ssh2_sftp_realpath( $s, '.' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $fp && '' !== $got ) {
			$this->remember( 'SHA1:' . $got );
		}
		$this->ssh  = $c;
		$this->sftp = $s;
		$this->home = rtrim( (string) $home, '/' );
		return true;
	}

	private function connect_seclib( $host, $port, $user ) {
		$s  = new \phpseclib3\Net\SFTP( $host, $port, 30 );
		$hk = $s->getServerPublicHostKey();
		if ( ! $hk || false === strpos( $hk, ' ' ) ) {
			return new WP_Error( 'sftp_connect', 'connection failed' );
		}
		$blob = base64_decode( substr( strrchr( $hk, ' ' ), 1 ), true );
		$fp   = self::fp_parse( $this->opt( 'fingerprint', '' ) );
		if ( $fp && ( ! $blob || ! hash_equals( $fp[1], self::fp_of_blob( $blob, $fp[0] ) ) ) ) {
			return new WP_Error( 'sftp_hostkey', 'host key changed' );
		}
		$pw  = (string) $this->opt( 'password', '' );
		$pk  = trim( str_replace( "\r\n", "\n", (string) $this->opt( 'private_key', '' ) ) );
		$cred = $pw;
		if ( '' !== $pk ) {
			try {
				$cred = \phpseclib3\Crypt\PublicKeyLoader::load( $pk . "\n", '' === $pw ? false : $pw );
			} catch ( \Throwable $e ) {
				return new WP_Error( 'sftp_key', 'private key not usable' );
			}
		}
		if ( ( '' === $pw && '' === $pk ) || ! $s->login( $user, $cred ) ) {
			return new WP_Error( 'sftp_login', 'login failed' );
		}
		if ( ! $fp && $blob ) {
			$this->remember( 'SHA256:' . self::fp_of_blob( $blob, 'sha256' ) );
		}
		$this->ssh = $s;
		return true;
	}

	public function close() {
		if ( 'seclib' === $this->eng && $this->ssh ) {
			try {
				$this->ssh->disconnect();
			} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement
			}
		} elseif ( $this->ssh && function_exists( 'ssh2_disconnect' ) ) {
			@ssh2_disconnect( $this->ssh ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$this->ssh  = null;
		$this->sftp = null;
		$this->eng  = '';
	}

	/* -------------------------------------------------------------- primitives */

	private static function safe( $p ) {
		return false === strpos( $p, '..' ) && false === strpos( $p, "\0" );
	}

	/** ssh2: stream wrapper address of a path ( the wrapper does not decode, so the raw path is used ). */
	private function url( $path ) {
		return 'ssh2.sftp://' . (int) $this->sftp . $this->home . '/' . ltrim( $path, '/' );
	}

	private function abs( $path ) {
		return $this->home . '/' . ltrim( $path, '/' );
	}

	private function mkdirs( $dir ) {
		$cur = '';
		foreach ( array_filter( explode( '/', trim( $dir, '/' ) ), 'strlen' ) as $seg ) {
			$cur .= ( '' === $cur ? '' : '/' ) . $seg;
			if ( isset( $this->made[ $cur ] ) ) {
				continue;
			}
			if ( 'ssh2' === $this->eng ) {
				if ( ! @ssh2_sftp_stat( $this->sftp, $this->abs( $cur ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
					@ssh2_sftp_mkdir( $this->sftp, $this->abs( $cur ), 0700 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				}
			} elseif ( ! $this->ssh->is_dir( $cur ) ) {
				$this->ssh->mkdir( $cur );
			}
			$this->made[ $cur ] = true;
		}
	}

	/** Entries of a folder: name => 'dir'|'file'; null = missing. */
	private function entries( $dir ) {
		$out = array();
		if ( 'ssh2' === $this->eng ) {
			$p = '' === $dir ? $this->home : $this->abs( $dir );
			if ( ! @ssh2_sftp_stat( $this->sftp, '' === $p ? '/' : $p ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
				return null;
			}
			$h = @opendir( '' === $dir ? 'ssh2.sftp://' . (int) $this->sftp . ( '' === $this->home ? '/' : $this->home ) : $this->url( $dir ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
			if ( ! $h ) {
				return null;
			}
			while ( false !== ( $n = readdir( $h ) ) ) { // phpcs:ignore WordPress.CodeAnalysis.AssignmentInCondition
				if ( '.' === $n || '..' === $n ) {
					continue;
				}
				$st         = @ssh2_sftp_stat( $this->sftp, $p . '/' . $n ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
				$out[ $n ] = ( $st && isset( $st['mode'] ) && 040000 === ( $st['mode'] & 0170000 ) ) ? 'dir' : 'file';
			}
			closedir( $h );
			return $out;
		}
		$l = $this->ssh->rawlist( '' === $dir ? '.' : $dir );
		if ( ! is_array( $l ) ) {
			return null;
		}
		foreach ( $l as $n => $a ) {
			if ( '.' === $n || '..' === $n ) {
				continue;
			}
			$out[ (string) $n ] = ( isset( $a['type'] ) && 2 === (int) $a['type'] ) ? 'dir' : 'file';
		}
		return $out;
	}

	private function rm_tree( $path, $depth = 0 ) {
		if ( $depth > 6 ) {
			return false;
		}
		if ( 'seclib' === $this->eng ) {
			return null === $this->entries( $path ) ? true : (bool) $this->ssh->delete( $path, true );
		}
		$e = $this->entries( $path );
		if ( null === $e ) {
			return true;
		}
		foreach ( $e as $n => $t ) {
			if ( 'dir' === $t ) {
				$this->rm_tree( $path . '/' . $n, $depth + 1 );
			} else {
				@ssh2_sftp_unlink( $this->sftp, $this->abs( $path . '/' . $n ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}
		return (bool) @ssh2_sftp_rmdir( $this->sftp, $this->abs( $path ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	/* ------------------------------------------------------------ target calls */

	public function put( $rel, $data ) {
		if ( ! self::safe( $rel ) ) {
			return new WP_Error( 'sftp_name', 'name' );
		}
		$c = $this->connect();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$path = $this->full( $rel );
		try {
			if ( false !== strpos( $path, '/' ) ) {
				$this->mkdirs( dirname( $path ) );
			}
			if ( 'ssh2' === $this->eng ) {
				$fh = @fopen( $this->url( $path ), 'wb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
				$ok = (bool) $fh;
				$n  = strlen( $data );
				for ( $o = 0; $ok && $o < $n; ) {
					$w = @fwrite( $fh, substr( $data, $o, 262144 ) ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
					if ( ! $w ) {
						$ok = false;
					} else {
						$o += $w;
					}
				}
				if ( $fh ) {
					fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				}
			} else {
				$ok = (bool) $this->ssh->put( $path, (string) $data );
			}
		} catch ( \Throwable $e ) {
			$ok = false;
		}
		if ( ! $ok ) {
			$this->close();
			return new WP_Error( 'sftp_put', 'upload failed' );
		}
		return true;
	}

	/** Downloads into a fresh local file. @return true|WP_Error */
	private function download( $rel, $file ) {
		if ( ! self::safe( $rel ) ) {
			return new WP_Error( 'sftp_name', 'name' );
		}
		$c = $this->connect();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$path = $this->full( $rel );
		try {
			if ( 'ssh2' === $this->eng ) {
				$in  = @fopen( $this->url( $path ), 'rb' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
				$out = fopen( $file, 'wb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				$ok  = $in && $out && false !== stream_copy_to_stream( $in, $out );
				if ( $in ) {
					fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				}
				if ( $out ) {
					fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
				}
			} else {
				$ok = (bool) $this->ssh->get( $path, $file );
			}
		} catch ( \Throwable $e ) {
			$ok = false;
		}
		if ( ! $ok ) {
			$this->close();
			return new WP_Error( 'sftp_get', 'download failed' );
		}
		return true;
	}

	public function get( $rel ) {
		$tmp = wp_tempnam( 'empsftp' );
		$r   = $this->download( $rel, $tmp );
		$d   = is_wp_error( $r ) ? $r : file_get_contents( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
		return false === $d ? new WP_Error( 'read', 'read' ) : $d;
	}

	public function get_to( $rel, $dest ) {
		$tmp = wp_tempnam( 'empsftp' );
		$r   = $this->download( $rel, $tmp );
		if ( is_wp_error( $r ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
			return $r;
		}
		$in  = fopen( $tmp, 'rb' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		$out = fopen( $dest, 'ab' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $in || ! $out ) {
			return new WP_Error( 'write', 'write' );
		}
		stream_copy_to_stream( $in, $out );
		fclose( $in ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fclose( $out ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
		return true;
	}

	public function dirs() {
		$c = $this->connect();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		try {
			$e = $this->entries( $this->base() );
		} catch ( \Throwable $x ) {
			$this->close();
			return new WP_Error( 'sftp_list', 'listing failed' );
		}
		if ( null === $e ) {
			return array(); // nothing saved yet
		}
		return array_keys( array_filter( $e, static function ( $t ) {
			return 'dir' === $t;
		} ) );
	}

	public function remove( $name ) {
		$name = trim( (string) $name, '/' );
		if ( '' === $name || ! self::safe( $name ) ) {
			return new WP_Error( 'sftp_name', 'name' );
		}
		$c = $this->connect();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		try {
			$ok = $this->rm_tree( $this->full( $name ) );
		} catch ( \Throwable $e ) {
			$ok = false;
		}
		return $ok ? true : new WP_Error( 'sftp_delete', 'delete failed' );
	}
}
