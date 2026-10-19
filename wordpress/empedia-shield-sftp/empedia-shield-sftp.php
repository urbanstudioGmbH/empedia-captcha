<?php
/**
 * Plugin Name:       EMPEDIA Shield SFTP
 * Plugin URI:        https://empedia.cloud
 * Description:       Adds SFTP (SSH) as a storage target for the encrypted backups of EMPEDIA Shield. Brings its own SSH library (phpseclib).
 * Version:           1.0.0
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Requires Plugins:  empedia-shield
 * Author:            urbanstudio GmbH
 * Author URI:        https://urbanstudio.de
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       empedia-shield-sftp
 * Domain Path:       /languages
 *
 * Add-on for EMPEDIA Shield ( empedia-shield ). It is delivered from empedia.cloud, not through wordpress.org, and updates itself
 * from there ( signed packages, see includes/class-empedia-updater.php ). EMPEDIA Shield itself contains no SSH library.
 *
 * How it plugs in: EMPEDIA Shield asks the filter 'empedia_shield_backup_target_types' for additional backup target types.
 * This add-on answers with the type 'sftp' ( label, form fields, class ). The class extends Empedia_Cloud_Target and
 * implements upload, download, listing and deleting; Shield does the rest ( schedule, encryption, restore, pruning ).
 *
 * @package EmpediaShieldSftp
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'EMPEDIA_SHIELD_SFTP_VERSION', '1.0.0' );
define( 'EMPEDIA_SHIELD_SFTP_FILE', __FILE__ );
define( 'EMPEDIA_SHIELD_SFTP_DIR', plugin_dir_path( __FILE__ ) );

require_once EMPEDIA_SHIELD_SFTP_DIR . 'includes/class-empedia-updater.php';

/** Is EMPEDIA Shield ( with the target extension point, 1.8.0 or newer ) loaded? */
function empedia_shield_sftp_host_ready() {
	return class_exists( 'Empedia_Cloud_Target', false ) && class_exists( 'Empedia_Cloud_Targets', false ) && method_exists( 'Empedia_Cloud_Targets', 'addon_types' );
}

/** The SFTP type for the backup settings of EMPEDIA Shield. */
function empedia_shield_sftp_register_type( $types ) {
	if ( ! is_array( $types ) || ! empedia_shield_sftp_host_ready() ) {
		return $types;
	}
	if ( ! class_exists( 'Empedia_Cloud_Target_Sftp', false ) ) {
		require_once EMPEDIA_SHIELD_SFTP_DIR . 'includes/class-empedia-sftp-target.php';
	}
	$types['sftp'] = array(
		'label'  => __( 'SFTP (SSH)', 'empedia-shield-sftp' ),
		'class'  => 'Empedia_Cloud_Target_Sftp',
		'fields' => array(
			'host'        => array( 'label' => __( 'Server', 'empedia-shield-sftp' ), 'type' => 'text', 'required' => true ),
			'port'        => array( 'label' => __( 'Port', 'empedia-shield-sftp' ), 'type' => 'text', 'required' => false, 'help' => __( 'Default 22.', 'empedia-shield-sftp' ) ),
			'user'        => array( 'label' => __( 'User', 'empedia-shield-sftp' ), 'type' => 'text', 'required' => true ),
			'password'    => array( 'label' => __( 'Password', 'empedia-shield-sftp' ), 'type' => 'password', 'required' => false, 'help' => __( 'Password or private key.', 'empedia-shield-sftp' ) ),
			'private_key' => array( 'label' => __( 'Private key', 'empedia-shield-sftp' ), 'type' => 'textarea', 'required' => false, 'help' => __( 'Paste the private key (OpenSSH or PEM). Leave empty to use the password.', 'empedia-shield-sftp' ) ),
			'fingerprint' => array( 'label' => __( 'Server fingerprint', 'empedia-shield-sftp' ), 'type' => 'text', 'required' => false, 'help' => __( 'SHA256 fingerprint of the server key. It is remembered on the first connection if you leave this empty.', 'empedia-shield-sftp' ) ),
			'path'        => array( 'label' => __( 'Folder', 'empedia-shield-sftp' ), 'type' => 'text', 'required' => false, 'help' => __( 'Folder for the backups, for example empedia-backups. It is created if needed.', 'empedia-shield-sftp' ) ),
		),
	);
	return $types;
}
add_filter( 'empedia_shield_backup_target_types', 'empedia_shield_sftp_register_type' );

/** Texts, update check, notice when EMPEDIA Shield is missing or too old. */
function empedia_shield_sftp_boot() {
	load_plugin_textdomain( 'empedia-shield-sftp', false, dirname( plugin_basename( EMPEDIA_SHIELD_SFTP_FILE ) ) . '/languages' );
	$base = class_exists( 'Empedia_Cloud_Client', false ) ? Empedia_Cloud_Client::base() : untrailingslashit( apply_filters( 'empedia_cloud_url', defined( 'EMPEDIA_CLOUD_URL' ) ? EMPEDIA_CLOUD_URL : 'https://empedia.cloud' ) );
	Empedia_Plugin_Updater::register( EMPEDIA_SHIELD_SFTP_FILE, EMPEDIA_SHIELD_SFTP_VERSION, $base );
	if ( ! empedia_shield_sftp_host_ready() ) {
		add_action(
			'admin_notices',
			static function () {
				if ( current_user_can( 'activate_plugins' ) ) {
					echo '<div class="notice notice-warning"><p>' . esc_html__( 'EMPEDIA Shield SFTP needs EMPEDIA Shield 1.8.0 or newer. Please install and activate EMPEDIA Shield (or update it); until then the SFTP target is not available.', 'empedia-shield-sftp' ) . '</p></div>';
				}
			}
		);
	}
}
add_action( 'plugins_loaded', 'empedia_shield_sftp_boot', 20 );
