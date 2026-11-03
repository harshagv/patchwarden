<?php
/**
 * Plugin Name:       Patchwarden
 * Plugin URI:        https://patchwarden.harshagv.me/
 * Description:       Reports your PHP version and plugin list to Patchwarden, and runs the plugin updates you approve in your Patchwarden dashboard. No password is ever shared.
 * Version:           0.1.0
 * Requires at least: 6.0
 * Requires PHP:      7.4
 * Author:            Patchwarden
 * License:           GPL-2.0-or-later
 * License URI:       https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain:       patchwarden
 *
 * @package Patchwarden
 */

defined( 'ABSPATH' ) || exit;

define( 'PATCHWARDEN_VERSION', '0.1.0' );
define( 'PATCHWARDEN_OPTION_KEY', 'patchwarden_api_key' );
define( 'PATCHWARDEN_OPTION_STATUS', 'patchwarden_status' );
define( 'PATCHWARDEN_REPORT_HOOK', 'patchwarden_report_event' );
define( 'PATCHWARDEN_ACTIONS_HOOK', 'patchwarden_actions_event' );

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/class-patchwarden-client.php';

register_activation_hook( __FILE__, 'patchwarden_activate' );
register_deactivation_hook( __FILE__, 'patchwarden_deactivate' );

add_action( PATCHWARDEN_REPORT_HOOK, 'patchwarden_send_report' );
add_action( PATCHWARDEN_ACTIONS_HOOK, 'patchwarden_run_actions' );
add_action( 'admin_menu', 'patchwarden_admin_menu' );
add_action( 'admin_post_patchwarden_save_key', 'patchwarden_handle_save_key' );

/**
 * Schedule the twice-daily report and the hourly check for approved actions.
 */
function patchwarden_activate() {
	if ( ! wp_next_scheduled( PATCHWARDEN_REPORT_HOOK ) ) {
		wp_schedule_event( time() + 60, 'twicedaily', PATCHWARDEN_REPORT_HOOK );
	}
	if ( ! wp_next_scheduled( PATCHWARDEN_ACTIONS_HOOK ) ) {
		wp_schedule_event( time() + 120, 'hourly', PATCHWARDEN_ACTIONS_HOOK );
	}
}

/**
 * Stop the schedule. The key stays until the plugin is deleted (see uninstall.php).
 */
function patchwarden_deactivate() {
	wp_clear_scheduled_hook( PATCHWARDEN_REPORT_HOOK );
	wp_clear_scheduled_hook( PATCHWARDEN_ACTIONS_HOOK );
}

/**
 * Remember the outcome of the last call, for the settings page. Never stores the key.
 *
 * @param bool   $ok      Whether it worked.
 * @param string $message Plain-language result.
 */
function patchwarden_set_status( $ok, $message ) {
	$status            = get_option( PATCHWARDEN_OPTION_STATUS, array() );
	$status            = is_array( $status ) ? $status : array();
	$status['ok']      = (bool) $ok;
	$status['message'] = substr( (string) $message, 0, 300 );
	$status['time']    = time();
	if ( $ok ) {
		$status['last_report'] = time();
	}
	update_option( PATCHWARDEN_OPTION_STATUS, $status, false );
}

/**
 * The slug WordPress.org uses for a plugin file, e.g. "akismet/akismet.php" -> "akismet".
 *
 * @param string $file Plugin file relative to the plugins folder.
 * @return string
 */
function patchwarden_plugin_slug( $file ) {
	$dir = dirname( $file );
	return ( '.' === $dir ) ? basename( $file, '.php' ) : $dir;
}

/**
 * What we report: versions and the plugin/theme inventory. No users, no content, no settings.
 *
 * @return array
 */
function patchwarden_collect_report() {
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$plugin_updates = get_site_transient( 'update_plugins' );
	$theme_updates  = get_site_transient( 'update_themes' );

	$plugins = array();
	foreach ( get_plugins() as $file => $data ) {
		$update    = ( is_object( $plugin_updates ) && isset( $plugin_updates->response[ $file ]->new_version ) )
			? $plugin_updates->response[ $file ]->new_version : '';
		$plugins[] = array(
			'slug'             => patchwarden_plugin_slug( $file ),
			'file'             => $file,
			'name'             => isset( $data['Name'] ) ? $data['Name'] : '',
			'version'          => isset( $data['Version'] ) ? $data['Version'] : '',
			'active'           => is_plugin_active( $file ),
			'update_available' => $update,
		);
	}

	$themes = array();
	$active = get_stylesheet();
	foreach ( wp_get_themes() as $stylesheet => $theme ) {
		$update   = ( is_object( $theme_updates ) && isset( $theme_updates->response[ $stylesheet ]['new_version'] ) )
			? $theme_updates->response[ $stylesheet ]['new_version'] : '';
		$themes[] = array(
			'slug'             => $stylesheet,
			'name'             => $theme->get( 'Name' ),
			'version'          => $theme->get( 'Version' ),
			'active'           => ( $stylesheet === $active ),
			'update_available' => $update,
		);
	}

	return array(
		'site_url'       => home_url(),
		'php_version'    => PHP_VERSION,
		'wp_version'     => get_bloginfo( 'version' ),
		'plugin_version' => PATCHWARDEN_VERSION,
		'plugins'        => $plugins,
		'themes'         => $themes,
	);
}

/**
 * Send the report to Patchwarden.
 *
 * @return bool
 */
function patchwarden_send_report() {
	$client = Patchwarden_Client::from_options();
	if ( is_wp_error( $client ) ) {
		patchwarden_set_status( false, $client->get_error_message() );
		return false;
	}
	$response = $client->request( 'POST', '/api/plugin/report', patchwarden_collect_report() );
	if ( is_wp_error( $response ) ) {
		patchwarden_set_status( false, $response->get_error_message() );
		return false;
	}
	patchwarden_set_status( true, __( 'Connected. Your site was checked.', 'patchwarden' ) );
	return true;
}

/**
 * Pull the actions the owner approved in the Patchwarden dashboard, run them, and report back.
 */
function patchwarden_run_actions() {
	$client = Patchwarden_Client::from_options();
	if ( is_wp_error( $client ) ) {
		return;
	}
	$response = $client->request( 'GET', '/api/plugin/actions' );
	if ( is_wp_error( $response ) || empty( $response['actions'] ) || ! is_array( $response['actions'] ) ) {
		return;
	}
	foreach ( $response['actions'] as $action ) {
		if ( ! is_array( $action ) || empty( $action['id'] ) ) {
			continue;
		}
		$kind    = isset( $action['kind'] ) ? (string) $action['kind'] : '';
		$payload = ( isset( $action['payload'] ) && is_array( $action['payload'] ) ) ? $action['payload'] : array();
		if ( 'update_component' === $kind ) {
			$result = patchwarden_update_component( $payload );
		} elseif ( 'report_now' === $kind ) {
			$result = array(
				'ok'     => patchwarden_send_report(),
				'detail' => 'Report sent.',
			);
		} else {
			// Only the actions this plugin knows are ever run.
			$result = array(
				'ok'     => false,
				'detail' => 'This version of the Patchwarden plugin does not support that action.',
			);
		}
		$client->request( 'POST', '/api/plugin/actions/' . absint( $action['id'] ) . '/result', $result );
	}
	patchwarden_send_report();
}

/**
 * Update one installed plugin or theme through WordPress's own updater (from WordPress.org).
 *
 * @param array $payload Action payload: type, slug, file.
 * @return array ok, detail, version.
 */
function patchwarden_update_component( $payload ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$type = isset( $payload['type'] ) ? (string) $payload['type'] : '';
	$slug = isset( $payload['slug'] ) ? sanitize_key( $payload['slug'] ) : '';

	if ( 'plugin' === $type ) {
		$file    = isset( $payload['file'] ) ? (string) $payload['file'] : '';
		$plugins = get_plugins();
		// Only a plugin that is installed here, and whose folder matches the slug.
		if ( ! isset( $plugins[ $file ] ) || patchwarden_plugin_slug( $file ) !== $slug ) {
			return array( 'ok' => false, 'detail' => 'That plugin is not installed on this site.' );
		}
		$upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
		$result   = $upgrader->upgrade( $file );
		wp_clean_plugins_cache();
		$plugins = get_plugins();
		$version = isset( $plugins[ $file ]['Version'] ) ? $plugins[ $file ]['Version'] : '';
	} elseif ( 'theme' === $type ) {
		$theme = wp_get_theme( $slug );
		if ( ! $theme->exists() ) {
			return array( 'ok' => false, 'detail' => 'That theme is not installed on this site.' );
		}
		$upgrader = new Theme_Upgrader( new Automatic_Upgrader_Skin() );
		$result   = $upgrader->upgrade( $slug );
		wp_clean_themes_cache();
		$version = wp_get_theme( $slug )->get( 'Version' );
	} else {
		return array( 'ok' => false, 'detail' => 'Unknown component type.' );
	}

	if ( is_wp_error( $result ) || ! $result ) {
		return array(
			'ok'      => false,
			'detail'  => is_wp_error( $result ) ? $result->get_error_message() : 'WordPress could not update it.',
			'version' => $version,
		);
	}
	return array(
		'ok'      => true,
		'detail'  => 'Updated.',
		'version' => $version,
	);
}

/**
 * Settings > Patchwarden.
 */
function patchwarden_admin_menu() {
	add_options_page( 'Patchwarden', 'Patchwarden', 'manage_options', 'patchwarden', 'patchwarden_render_settings' );
}

/**
 * The settings page: paste the key from the Patchwarden dashboard, done.
 */
function patchwarden_render_settings() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$key    = get_option( PATCHWARDEN_OPTION_KEY, '' );
	$status = get_option( PATCHWARDEN_OPTION_STATUS, array() );
	echo '<div class="wrap"><h1>' . esc_html__( 'Patchwarden', 'patchwarden' ) . '</h1>';
	if ( is_array( $status ) && ! empty( $status['message'] ) ) {
		$class = empty( $status['ok'] ) ? 'notice-error' : 'notice-success';
		echo '<div class="notice ' . esc_attr( $class ) . '"><p>' . esc_html( $status['message'] ) . '</p></div>';
	}
	echo '<p>' . esc_html__( 'Paste the key from your Patchwarden dashboard. We never ask for a password.', 'patchwarden' ) . '</p>';
	echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">';
	echo '<input type="hidden" name="action" value="patchwarden_save_key">';
	wp_nonce_field( 'patchwarden_save_key' );
	// The saved key is never printed back; only its first characters.
	$placeholder = $key ? substr( $key, 0, 7 ) . '…' : 'pw_…';
	echo '<p><input type="password" name="patchwarden_api_key" autocomplete="off" class="regular-text" placeholder="' . esc_attr( $placeholder ) . '"></p>';
	submit_button( __( 'Save and connect', 'patchwarden' ) );
	echo '</form></div>';
}

/**
 * Save the key (admins only, with a nonce), then report straight away.
 */
function patchwarden_handle_save_key() {
	if ( ! current_user_can( 'manage_options' ) ) {
		wp_die( esc_html__( 'You are not allowed to do that.', 'patchwarden' ) );
	}
	check_admin_referer( 'patchwarden_save_key' );
	$key = isset( $_POST['patchwarden_api_key'] ) ? sanitize_text_field( wp_unslash( $_POST['patchwarden_api_key'] ) ) : '';
	if ( ! preg_match( '/^pw_[A-Za-z0-9_-]{20,80}$/', $key ) ) {
		patchwarden_set_status( false, __( 'That does not look like a Patchwarden key. Copy it again from your dashboard.', 'patchwarden' ) );
	} else {
		update_option( PATCHWARDEN_OPTION_KEY, $key, false );
		patchwarden_activate();
		patchwarden_send_report();
	}
	wp_safe_redirect( admin_url( 'options-general.php?page=patchwarden' ) );
	exit;
}
