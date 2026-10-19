<?php
/**
 * Plugin Name:       EMPEDIA Shield – Security, Firewall & Backups
 * Plugin URI:        https://empedia.cloud
 * Description:       Security settings, sign-in protection with two-factor authentication and passkeys, file integrity check, firewall, encrypted backups and bot protection (EMPEDIAcaptcha) – with an optional connection to EMPEDIAcloud.
 * Version:           1.8.5
 * Requires at least: 5.8
 * Requires PHP:      7.4
 * Author:            urbanstudio GmbH
 * Author URI:        https://urbanstudio.de
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       empedia-shield
 * Domain Path:       /languages
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * The former plugin "EMPEDIAcloud" (empedia-cloud/empedia-cloud.php) uses the same classes: when it is active, this plugin does not
 * start (no double hooks, no fatal errors) and asks to deactivate it. The settings and data are shared, nothing is lost.
 * The former stand-alone "EMPEDIAcaptcha" plugin is replaced by the built-in module: while it is active, the built-in module stays off.
 */
function empedia_shield_active_legacy() {
	$active = (array) get_option( 'active_plugins', array() );
	if ( is_multisite() ) {
		$active = array_merge( $active, array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
	}
	return array(
		'cloud'   => defined( 'EMPEDIA_CLOUD_VERSION' ) || class_exists( 'Empedia_Cloud_Plugin', false ) || in_array( 'empedia-cloud/empedia-cloud.php', $active, true ),
		'captcha' => class_exists( 'Empedia_Captcha_Plugin', false ) || in_array( 'empedia-captcha/empedia-captcha.php', $active, true ),
	);
}

$empedia_shield_legacy = empedia_shield_active_legacy();
if ( $empedia_shield_legacy['cloud'] ) {
	add_action(
		'admin_notices',
		static function () {
			if ( current_user_can( 'activate_plugins' ) ) {
				echo '<div class="notice notice-error"><p>' . esc_html__( 'EMPEDIA Shield replaces the plugin “EMPEDIAcloud”. Please deactivate and delete “EMPEDIAcloud” (and “EMPEDIAcaptcha”, if installed) on the Plugins page. Your settings are kept. EMPEDIA Shield stays off until then.', 'empedia-shield' ) . '</p></div>';
			}
		}
	);
	return;
}

define( 'EMPEDIA_CLOUD_VERSION', '1.8.5' );
define( 'EMPEDIA_CLOUD_FILE', __FILE__ );
define( 'EMPEDIA_CLOUD_DIR', plugin_dir_path( __FILE__ ) );
define( 'EMPEDIA_CLOUD_URL_BASE', plugin_dir_url( __FILE__ ) );

require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-client.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-inventory.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-hardening.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-connect.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-atomic.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-firewall.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-totp.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-webauthn.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-protect.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-protect-admin.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-sso.php';
if ( ! $empedia_shield_legacy['captcha'] ) {
	require_once EMPEDIA_CLOUD_DIR . 'includes/captcha/class-empedia-captcha.php';
}
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-bots.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-scanner.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-files-admin.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-firewall-admin.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-watch.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-target.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-bunny.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-backup.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-restore.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-backup-report.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-backup-admin.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-comments.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-admin.php';
require_once EMPEDIA_CLOUD_DIR . 'includes/class-empedia-plugin.php';

register_activation_hook( __FILE__, array( 'Empedia_Cloud_Plugin', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Empedia_Cloud_Plugin', 'deactivate' ) );

Empedia_Cloud_Plugin::init();
Empedia_Cloud_Firewall::boot(); // no effect when the firewall is switched off; with the must-use loader it already ran earlier

if ( class_exists( 'Empedia_Captcha_Plugin', false ) && ! $empedia_shield_legacy['captcha'] ) {
	Empedia_Captcha_Plugin::boot();
	add_action( 'plugins_loaded', 'empedia_captcha_gate_boot', 1 );
} elseif ( $empedia_shield_legacy['captcha'] ) {
	add_action(
		'admin_notices',
		static function () {
			if ( current_user_can( 'activate_plugins' ) ) {
				echo '<div class="notice notice-warning"><p>' . esc_html__( 'Bot protection is now part of EMPEDIA Shield. Please deactivate and delete the separate plugin “EMPEDIAcaptcha” – until then its own copy keeps running and the built-in bot protection stays off. Your keys and settings are kept.', 'empedia-shield' ) . '</p></div>';
			}
		}
	);
}
