<?php
/**
 * Atomic counters and one-time claims on the options table ( INSERT … ON DUPLICATE KEY ), so parallel requests
 * cannot all pass the same check. Rows are small and removed by cleanup().
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! class_exists( 'Empedia_Cloud_Atomic', false ) ) {

class Empedia_Cloud_Atomic {

	const PREFIX = 'empedia_atm_';

	/** Row name: derived from the constants of wp-config.php only ( also usable before pluggable.php is loaded ). */
	private static function name( $key ) {
		$secret = ( defined( 'AUTH_KEY' ) ? AUTH_KEY : '' ) . ( defined( 'AUTH_SALT' ) ? AUTH_SALT : '' ) . 'empedia';
		return self::PREFIX . substr( hash_hmac( 'sha256', (string) $key, $secret ), 0, 40 );
	}

	/** Plain counter ( no expiry ): option row `$name`, incremented atomically. */
	public static function count( $name ) {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, '1', 'no') ON DUPLICATE KEY UPDATE option_value = option_value + 1", $name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/** All counters whose name starts with the prefix: name => value. */
	public static function counters( $prefix ) {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( $prefix ) . '%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$out  = array();
		foreach ( (array) $rows as $r ) {
			$out[ $r->option_name ] = (int) $r->option_value;
		}
		return $out;
	}

	/** Deletes counters with the prefix whose date part ( after the prefix, YYYY-MM-DD ) is older than the given day. */
	public static function purge_counters( $prefix, $before_day ) {
		foreach ( self::counters( $prefix ) as $name => $v ) {
			if ( preg_match( '/^' . preg_quote( $prefix, '/' ) . '(\d{4}-\d{2}-\d{2})_/', $name, $m ) && $m[1] < $before_day ) {
				delete_option( $name );
			}
		}
	}

	/** Counts a hit inside a window of $secs seconds; returns the number of hits in the current window. */
	public static function hit( $key, $secs ) {
		global $wpdb;
		$name = self::name( $key );
		$now  = time();
		$exp  = $now + max( 1, (int) $secs );
		$wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery
			$wpdb->prepare(
				"INSERT INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')
				 ON DUPLICATE KEY UPDATE option_value = IF(CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) < %d, %s, CONCAT(SUBSTRING_INDEX(option_value, '|', 1), '|', CAST(SUBSTRING_INDEX(option_value, '|', -1) AS UNSIGNED) + 1))",
				$name,
				$exp . '|1',
				$now,
				$exp . '|1'
			)
		);
		$v = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", $name ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$p = explode( '|', (string) $v );
		return isset( $p[1] ) ? (int) $p[1] : 1;
	}

	/** Forgets a counter. */
	public static function reset( $key ) {
		global $wpdb;
		$wpdb->delete( $wpdb->options, array( 'option_name' => self::name( $key ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/** true for exactly one caller per key ( until the claim expires ). */
	public static function claim( $key, $secs = 3600 ) {
		global $wpdb;
		$name = self::name( 'claim:' . $key );
		$now  = time();
		// An expired claim is removed first so a later legitimate use is possible.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name = %s AND CAST(option_value AS UNSIGNED) < %d", $name, $now ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		$n = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$wpdb->options} (option_name, option_value, autoload) VALUES (%s, %s, 'no')", $name, (string) ( $now + (int) $secs ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		return 1 === (int) $n;
	}

	/** Releases a claim early ( locks ). */
	public static function release( $key ) {
		global $wpdb;
		$wpdb->delete( $wpdb->options, array( 'option_name' => self::name( 'claim:' . $key ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}

	/** Is the claim currently held? */
	public static function locked( $key ) {
		global $wpdb;
		$v = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM {$wpdb->options} WHERE option_name = %s", self::name( 'claim:' . $key ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
		return null !== $v && (int) $v >= time();
	}

	/** Removes expired rows ( called from the daily cron ). */
	public static function cleanup() {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s AND CAST(SUBSTRING_INDEX(option_value, '|', 1) AS UNSIGNED) < %d", $wpdb->esc_like( self::PREFIX ) . '%', time() - HOUR_IN_SECONDS ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
	}
}

} // class_exists
