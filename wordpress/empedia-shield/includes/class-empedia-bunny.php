<?php
/**
 * Cloud storage target ( EMPEDIAcloud backup storage ): upload, list, fetch and delete of encrypted backups.
 *
 * The storage access keys are only ever requested for the moment they are needed ( per step ) and are never saved.
 * A backup is stored as <id>/<file>.pNNNNN parts ( 8 MB ) plus <id>/manifest.json ( written last ).
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

// phpcs:disable WordPress.WP.AlternativeFunctions -- backup archives are streamed in small chunks; WP_Filesystem cannot read or write partially.

class Empedia_Cloud_Bunny {

	const PART      = 8388608;
	const TR_STATUS = 'empedia_bunny_status';
	const TR_LIST   = 'empedia_bunny_list';
	const ESCROW    = 'empedia_backup_key_escrowed';

	/** @var array|WP_Error|null */
	private static $creds = null;

	/* ------------------------------------------------------------------ cloud */

	/** Storage state from the cloud ( cached for two minutes ). @return array|WP_Error */
	public static function status( $force = false ) {
		if ( ! $force ) {
			$c = get_transient( self::TR_STATUS );
			if ( is_array( $c ) ) {
				return $c;
			}
		}
		$r = Empedia_Cloud_Client::request( 'GET', '/backup/storage' );
		if ( ! is_wp_error( $r ) ) {
			set_transient( self::TR_STATUS, $r, 120 );
		}
		return $r;
	}

	public static function forget() {
		delete_transient( self::TR_STATUS );
		delete_transient( self::TR_LIST );
		self::$creds = null;
	}

	/** Is there an active zone ( from cache, no request )? */
	public static function has_zone() {
		$s = get_transient( self::TR_STATUS );
		return is_array( $s ) && ! empty( $s['zone'] ) && isset( $s['zone']['status'] ) && 'active' === $s['zone']['status'];
	}

	/** Uploads are wanted and possible. */
	public static function enabled() {
		return Empedia_Cloud_Client::is_connected() && self::has_zone();
	}

	public static function activate() {
		$r = Empedia_Cloud_Client::request( 'POST', '/backup/storage/activate', new stdClass(), true, 30 );
		self::forget();
		return $r;
	}

	/** Access data for this moment only. @return array|WP_Error */
	private static function creds() {
		if ( null === self::$creds ) {
			$r = Empedia_Cloud_Client::request( 'GET', '/backup/storage/credentials', null, true, 20 );
			self::$creds = ( is_wp_error( $r ) || empty( $r['endpoint'] ) || empty( $r['zone'] ) || empty( $r['write_key'] ) ) ? ( is_wp_error( $r ) ? $r : new WP_Error( 'creds', 'creds' ) ) : $r;
		}
		return self::$creds;
	}

	/** Makes sure the cloud holds the key of this site ( only sent when it changed ). @return true|WP_Error */
	public static function escrow_key() {
		$key = Empedia_Cloud_Backup::master_key();
		$h   = hash( 'sha256', $key );
		if ( get_option( self::ESCROW ) === $h ) {
			return true;
		}
		$r = Empedia_Cloud_Client::request( 'PUT', '/backup/key', array( 'key_b64' => base64_encode( $key ) ), true, 20 );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		update_option( self::ESCROW, $h, false );
		return true;
	}

	/** Key from the cloud ( recovery ). @return string|WP_Error base64 */
	public static function fetch_key() {
		$r = Empedia_Cloud_Client::request( 'GET', '/backup/key', null, true, 20 );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		return isset( $r['key_b64'] ) ? (string) $r['key_b64'] : new WP_Error( 'nokey', 'nokey' );
	}

	/* ------------------------------------------------------------------- http */

	private static function request( array $c, $method, $path, array $args = array() ) {
		$args += array(
			'method'      => $method,
			'timeout'     => 90,
			'redirection' => 0,
			'headers'     => array(),
		);
		$args['headers']['AccessKey'] = $c['write_key'];
		$args['headers']['Accept']    = 'application/json';
		$res = wp_remote_request( rtrim( $c['endpoint'], '/' ) . '/' . rawurlencode( $c['zone'] ) . '/' . ltrim( $path, '/' ), $args );
		if ( is_wp_error( $res ) ) {
			return new WP_Error( 'bunny_http', $res->get_error_message() );
		}
		$code = (int) wp_remote_retrieve_response_code( $res );
		if ( $code >= 400 ) {
			return new WP_Error( 'bunny_' . $code, 'http ' . $code );
		}
		return $res;
	}

	private static function rel( $id, $file ) {
		return preg_replace( '/[^A-Za-z0-9\-]/', '', $id ) . '/' . basename( $file );
	}

	public static function put_string( $path, $data ) {
		$c = self::creds();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$r = self::request( $c, 'PUT', $path, array( 'body' => $data, 'headers' => array( 'Content-Type' => 'application/octet-stream' ) ) );
		return is_wp_error( $r ) ? $r : true;
	}

	/** Uploads bytes $offset..$offset+$len of $file as one object. @return true|WP_Error */
	public static function upload_part( $id, $remote_name, $file, $offset, $len ) {
		$fh = fopen( $file, 'rb' );
		if ( ! $fh ) {
			return new WP_Error( 'read', 'read' );
		}
		fseek( $fh, $offset );
		$data = fread( $fh, $len );
		fclose( $fh );
		if ( strlen( (string) $data ) !== $len ) {
			return new WP_Error( 'read', 'read' );
		}
		return self::put_string( self::rel( $id, $remote_name ), $data );
	}

	/** Appends the object to $dest. @return true|WP_Error */
	public static function fetch_part( $id, $remote_name, $dest ) {
		$c = self::creds();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$tmp = $dest . '.dl';
		$r   = self::request( $c, 'GET', self::rel( $id, $remote_name ), array( 'stream' => true, 'filename' => $tmp ) );
		if ( is_wp_error( $r ) ) {
			@unlink( $tmp ); // phpcs:ignore WordPress.PHP.NoSilencedErrors,WordPress.WP.AlternativeFunctions
			return $r;
		}
		$in  = fopen( $tmp, 'rb' );
		$out = fopen( $dest, 'ab' );
		if ( ! $in || ! $out ) {
			return new WP_Error( 'write', 'write' );
		}
		stream_copy_to_stream( $in, $out );
		fclose( $in );
		fclose( $out );
		wp_delete_file( $tmp );
		return true;
	}

	/** Appends the object at $rel to $dest. @return true|WP_Error */
	public static function fetch_rel( $rel, $dest ) {
		$p = explode( '/', $rel, 2 );
		return self::fetch_part( $p[0], isset( $p[1] ) ? $p[1] : '', $dest );
	}

	/** Names of the folders at the top of the zone. @return string[]|WP_Error */
	public static function dir_names() {
		$c = self::creds();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$r = self::request( $c, 'GET', '' );
		if ( is_wp_error( $r ) ) {
			return $r;
		}
		$out = array();
		foreach ( (array) json_decode( wp_remote_retrieve_body( $r ), true ) as $d ) {
			if ( ! empty( $d['IsDirectory'] ) && ! empty( $d['ObjectName'] ) ) {
				$out[] = (string) $d['ObjectName'];
			}
		}
		return $out;
	}

	public static function get_string( $path ) {
		$c = self::creds();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$r = self::request( $c, 'GET', $path );
		return is_wp_error( $r ) ? $r : wp_remote_retrieve_body( $r );
	}

	public static function delete_backup( $id ) {
		$c = self::creds();
		if ( is_wp_error( $c ) ) {
			return $c;
		}
		$r = self::request( $c, 'DELETE', preg_replace( '/[^A-Za-z0-9\-]/', '', $id ) . '/' );
		delete_transient( self::TR_LIST );
		return is_wp_error( $r ) ? $r : true;
	}

	/** Backups in the cloud storage ( from their manifests ), newest first. @return array|WP_Error */
	public static function list_backups( $force = false ) {
		return Empedia_Cloud_Targets::backups( new Empedia_Cloud_Target_Bunny( 'cloud', array() ), $force );
	}

	/** Deletes the oldest backups beyond $keep. */
	public static function prune( $keep ) {
		Empedia_Cloud_Targets::prune( new Empedia_Cloud_Target_Bunny( 'cloud', array() ), $keep );
	}

	public static function part_name( $file, $i ) {
		return basename( $file ) . '.p' . sprintf( '%05d', $i );
	}
}


/** The EMPEDIAcloud storage as a target ( the access keys are fetched per run and never saved ). */
class Empedia_Cloud_Target_Bunny extends Empedia_Cloud_Target {

	public function put( $rel, $data ) {
		return Empedia_Cloud_Bunny::put_string( $rel, $data );
	}

	public function get( $rel ) {
		return Empedia_Cloud_Bunny::get_string( $rel );
	}

	public function get_to( $rel, $dest ) {
		return Empedia_Cloud_Bunny::fetch_rel( $rel, $dest );
	}

	public function dirs() {
		return Empedia_Cloud_Bunny::dir_names();
	}

	public function remove( $name ) {
		return Empedia_Cloud_Bunny::delete_backup( $name );
	}
}
