<?php
/**
 * Runs when the plugin is deleted in WordPress: removes every option and scheduled event it created,
 * and tells Patchwarden to revoke the key, so no data or key is left behind on either side.
 *
 * @package Patchwarden
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

if ( ! defined( 'PATCHWARDEN_OPTION_KEY' ) ) {
	define( 'PATCHWARDEN_OPTION_KEY', 'patchwarden_api_key' );
}
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/class-patchwarden-client.php';

$patchwarden_client = Patchwarden_Client::from_options();
if ( ! is_wp_error( $patchwarden_client ) ) {
	// Best effort: if Patchwarden cannot be reached, the owner can still revoke the key in the dashboard.
	$patchwarden_client->request( 'POST', '/api/plugin/disconnect', array() );
}

delete_option( 'patchwarden_api_key' );
delete_option( 'patchwarden_status' );
wp_clear_scheduled_hook( 'patchwarden_report_event' );
wp_clear_scheduled_hook( 'patchwarden_actions_event' );
