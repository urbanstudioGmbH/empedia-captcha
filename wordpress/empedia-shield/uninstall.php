<?php
/**
 * Removes everything the plugin stored: ends the connection (best effort), removes the marked .htaccess blocks, the must-use firewall loader
 * (if it was installed) and all options. ( empedia_plugins_auto_update: leftover of the former self-updater. )
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

define( 'EMPEDIA_CLOUD_VERSION', 'uninstall' );
require_once __DIR__ . '/includes/class-empedia-client.php';
require_once __DIR__ . '/includes/class-empedia-hardening.php';
require_once __DIR__ . '/includes/class-empedia-atomic.php';
require_once __DIR__ . '/includes/class-empedia-firewall.php';

if ( Empedia_Cloud_Client::is_connected() ) {
	Empedia_Cloud_Client::request( 'POST', '/disconnect', array(), true, 8 );
}
Empedia_Cloud_Hardening::revert_all();
Empedia_Cloud_Firewall::remove_mu();

foreach ( array( 'empedia_cloud_inventory', 'empedia_cloud_heartbeat', 'empedia_cloud_verify_retry', 'empedia_cloud_scan_tick', 'empedia_cloud_scan_daily', 'empedia_cloud_events_send' ) as $empedia_hook ) {
	wp_clear_scheduled_hook( $empedia_hook );
}
foreach ( array( 'empedia_cloud_conn', 'empedia_cloud_hardening', 'empedia_cloud_verify', 'empedia_cloud_verify_try', 'empedia_cloud_token_invalid', 'empedia_cloud_probes', 'empedia_cloud_cron_seen', 'empedia_cloud_last_sync', 'empedia_cloud_status_last', 'empedia_cloud_protect', 'empedia_cloud_protect_stats', 'empedia_cloud_scan_state', 'empedia_cloud_scan_result', 'empedia_cloud_scan_ignore', 'empedia_cloud_scanner', 'empedia_cloud_events', 'empedia_cloud_last_backup', 'empedia_cloud_fw', 'empedia_cloud_fw_remote', 'empedia_cloud_fw_samples', 'empedia_cloud_fw_legit', 'empedia_cloud_sso', 'empedia_cloud_comments', 'empedia_captcha', 'empedia_captcha_fails', 'empedia_plugins_auto_update' ) as $empedia_opt ) {
	delete_option( $empedia_opt );
}
delete_transient( 'empedia_cloud_status' );

// Second factors and passkeys of all users, and every short-lived entry ( tickets, counters, locks ).
foreach ( array( 'empedia_totp', 'empedia_totp_pending', 'empedia_totp_last', 'empedia_recovery', 'empedia_passkeys', 'empedia_wa_handle', 'empedia_sso_sub', 'empedia_known_ips' ) as $empedia_meta ) {
	delete_metadata( 'user', 0, $empedia_meta, '', true );
}
global $wpdb;
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'empedia\\_atm\\_%' OR option_name LIKE 'empedia\\_fw\\_cnt\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE '\\_transient\\_empedia\\_%' OR option_name LIKE '\\_transient\\_timeout\\_empedia\\_%' OR option_name LIKE '\\_site\\_transient\\_empedia\\_%' OR option_name LIKE '\\_site\\_transient\\_timeout\\_empedia\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
if ( is_multisite() ) {
	$wpdb->query( "DELETE FROM {$wpdb->sitemeta} WHERE meta_key LIKE '\\_site\\_transient\\_empedia\\_%' OR meta_key LIKE '\\_site\\_transient\\_timeout\\_empedia\\_%'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
}
