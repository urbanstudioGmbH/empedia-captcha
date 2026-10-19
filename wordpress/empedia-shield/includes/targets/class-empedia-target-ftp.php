<?php
/**
 * Storage target: FTP / FTPS ( PHP extension "ftp" ).
 *
 * Passive mode, binary transfer. With "tls" the control and data connections are encrypted ( explicit FTPS ).
 * Note: PHP does not verify the server certificate of an FTPS connection; prefer SFTP where possible.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Target_Ftp extends Empedia_Cloud_Target {

	/** @var resource|\FTP\Connection|null */
	private $conn = null;
	/** @var array Folders known to exist. */
	private $made = array();

	/** @return resource|\FTP\Connection|WP_Error */
	private function conn() {
		if ( $this->conn ) {
			return $this->conn;
		}
		if ( ! function_exists( 'ftp_connect' ) ) {
			return new WP_Error( 'ftp_missing', 'ftp extension missing' );
		}
		$host = (string) $this->opt( 'host', '' );
		$port = (int) $this->opt( 'port', 21 );
		if ( '' === $host || $port < 1 || $port > 65535 ) {
			return new WP_Error( 'ftp_config', 'config' );
		}
		$tls = ! empty( $this->cfg['tls'] );
		$c   = $tls ? @ftp_ssl_connect( $host, $port, 30 ) : @ftp_connect( $host, $port, 30 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! $c ) {
			return new WP_Error( 'ftp_connect', 'connection failed' );
		}
		if ( ! @ftp_login( $c, (string) $this->opt( 'user' ), (string) $this->opt( 'password' ) ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			@ftp_close( $c ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return new WP_Error( 'ftp_login', 'login failed' );
		}
		@ftp_pasv( $c, true ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( function_exists( 'ftp_set_option' ) ) {
			@ftp_set_option( $c, FTP_TIMEOUT_SEC, 120 ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$this->made = array();
		return $this->conn = $c;
	}

	/** Drops a connection that failed so the next call reconnects. */
	private function drop() {
		if ( $this->conn ) {
			@ftp_close( $this->conn ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		$this->conn = null;
	}

	public function close() {
		$this->drop();
	}

	private static function safe( $rel ) {
		return false === strpos( $rel, '..' ) && false === strpos( $rel, "\0" );
	}

	private function mkdirs( $c, $dir ) {
		$cur = '';
		foreach ( array_filter( explode( '/', trim( $dir, '/' ) ), 'strlen' ) as $seg ) {
			$cur .= ( '' === $cur ? '' : '/' ) . $seg;
			if ( isset( $this->made[ $cur ] ) ) {
				continue;
			}
			@ftp_mkdir( $c, $cur ); // phpcs:ignore WordPress.PHP.NoSilencedErrors -- fails when it exists; the upload shows real problems
			$this->made[ $cur ] = true;
		}
	}

	public function put( $rel, $data ) {
		if ( ! self::safe( $rel ) ) {
			return new WP_Error( 'ftp_name', 'name' );
		}
		$c = $this->conn();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$path = $this->full( $rel );
		if ( false !== strpos( $path, '/' ) ) {
			$this->mkdirs( $c, dirname( $path ) );
		}
		$fh = fopen( 'php://temp/maxmemory:' . ( 16 * 1048576 ), 'w+b' ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		fwrite( $fh, (string) $data ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		rewind( $fh );
		$ok = @ftp_fput( $c, $path, $fh, FTP_BINARY ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		fclose( $fh ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		if ( ! $ok ) {
			$this->drop();
			return new WP_Error( 'ftp_put', 'upload failed' );
		}
		return true;
	}

	public function get( $rel ) {
		$tmp = wp_tempnam( 'empftp' );
		$r   = $this->download( $rel, $tmp );
		if ( is_wp_error( $r ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
			return $r;
		}
		$d = file_get_contents( $tmp ); // phpcs:ignore WordPress.WP.AlternativeFunctions
		@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
		return false === $d ? new WP_Error( 'read', 'read' ) : $d;
	}

	/** Downloads to a fresh local file. @return true|WP_Error */
	private function download( $rel, $file ) {
		if ( ! self::safe( $rel ) ) {
			return new WP_Error( 'ftp_name', 'name' );
		}
		$c = $this->conn();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		if ( ! @ftp_get( $c, $file, $this->full( $rel ), FTP_BINARY ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			$this->drop();
			return new WP_Error( 'ftp_get', 'download failed' );
		}
		return true;
	}

	public function get_to( $rel, $dest ) {
		$tmp = wp_tempnam( 'empftp' );
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

	/**
	 * Entries of a folder: name => 'dir'|'file'. null = the folder does not exist.
	 *
	 * @return array|null
	 */
	private function entries( $c, $dir ) {
		$dir = '' === $dir ? '.' : $dir;
		$out = array();
		if ( function_exists( 'ftp_mlsd' ) ) {
			$l = @ftp_mlsd( $c, $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( is_array( $l ) ) {
				foreach ( $l as $e ) {
					$n = isset( $e['name'] ) ? basename( $e['name'] ) : '';
					$t = isset( $e['type'] ) ? $e['type'] : '';
					if ( '' === $n || in_array( $t, array( 'cdir', 'pdir' ), true ) || in_array( $n, array( '.', '..' ), true ) ) {
						continue;
					}
					$out[ $n ] = 'dir' === $t ? 'dir' : 'file';
				}
				return $out;
			}
		}
		// Fallback for servers without MLSD: listing + folder test.
		$cwd = @ftp_pwd( $c ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( '.' !== $dir && ! @ftp_chdir( $c, $dir ) ) { // phpcs:ignore WordPress.PHP.NoSilencedErrors
			return null;
		}
		$l = @ftp_nlist( $c, '.' ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		$l = is_array( $l ) ? $l : array();
		foreach ( $l as $p ) {
			$n = basename( $p );
			if ( '' === $n || '.' === $n || '..' === $n ) {
				continue;
			}
			$out[ $n ] = @ftp_chdir( $c, $n ) ? 'dir' : 'file'; // phpcs:ignore WordPress.PHP.NoSilencedErrors
			if ( 'dir' === $out[ $n ] ) {
				@ftp_cdup( $c ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}
		if ( $cwd ) {
			@ftp_chdir( $c, $cwd ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		}
		return $out;
	}

	public function dirs() {
		$c = $this->conn();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$e = $this->entries( $c, $this->base() );
		if ( null === $e ) {
			return array();
		}
		return array_keys( array_filter( $e, static function ( $t ) {
			return 'dir' === $t;
		} ) );
	}

	private function rm_tree( $c, $dir, $depth = 0 ) {
		if ( $depth > 6 ) {
			return false;
		}
		$e = $this->entries( $c, $dir );
		if ( null === $e ) {
			return true;
		}
		foreach ( $e as $n => $t ) {
			$p = $dir . '/' . $n;
			if ( 'dir' === $t ) {
				$this->rm_tree( $c, $p, $depth + 1 );
			} else {
				@ftp_delete( $c, $p ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
			}
		}
		return (bool) @ftp_rmdir( $c, $dir ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
	}

	public function remove( $name ) {
		$name = trim( (string) $name, '/' );
		if ( '' === $name || ! self::safe( $name ) ) {
			return new WP_Error( 'ftp_name', 'name' );
		}
		$c = $this->conn();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		return $this->rm_tree( $c, $this->full( $name ) ) ? true : new WP_Error( 'ftp_delete', 'delete failed' );
	}
}
