<?php
/**
 * Minimal autoloader for the bundled libraries ( no Composer needed ):
 *  - phpseclib 3 ( MIT, https://phpseclib.com ) in lib/phpseclib/  – namespace phpseclib3\
 *  - paragonie/constant_time_encoding ( MIT ) in lib/constant_time_encoding/  – namespace ParagonIE\ConstantTime\
 * Only used by the SFTP backup target of this add-on when the PHP extension ssh2 is not available.
 *
 * @package EmpediaShieldSftp
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

if ( ! defined( 'EMPEDIA_SHIELD_SFTP_LIB_LOADED' ) ) {
	define( 'EMPEDIA_SHIELD_SFTP_LIB_LOADED', true );
	spl_autoload_register(
		static function ( $class ) {
			$map = array(
				'phpseclib3\\'             => __DIR__ . '/phpseclib/',
				'ParagonIE\\ConstantTime\\' => __DIR__ . '/constant_time_encoding/',
			);
			foreach ( $map as $prefix => $dir ) {
				if ( 0 === strpos( $class, $prefix ) ) {
					$file = $dir . str_replace( '\\', '/', substr( $class, strlen( $prefix ) ) ) . '.php';
					if ( is_file( $file ) ) {
						require_once $file;
					}
					return;
				}
			}
		}
	);
	if ( is_file( __DIR__ . '/phpseclib/bootstrap.php' ) ) {
		require_once __DIR__ . '/phpseclib/bootstrap.php';
	}
}
