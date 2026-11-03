<?php
/**
 * A stand-in for the parts of WordPress the Patchwarden plugin uses, so tests run the real plugin code.
 *
 * WordPress core is NOT loaded. Options, cron, transients, plugins and themes live in a JSON "database"
 * (PATCHWARDEN_HARNESS_STATE); HTTP calls really go to the Patchwarden server under test (PATCHWARDEN_API_URL).
 *
 * Usage: php harness.php <command> [arg]
 *   activate | deactivate | save_key <key> | cron <hook> | settings_page | uninstall | dump
 */

$state_file = getenv( 'PATCHWARDEN_HARNESS_STATE' );
$GLOBALS['H'] = json_decode( (string) @file_get_contents( $state_file ), true ) ?: array();
$GLOBALS['H'] += array( 'options' => array(), 'cron' => array(), 'site_transients' => array(), 'plugins' => array(),
	'themes' => array(), 'stylesheet' => '', 'active_plugins' => array(), 'available_updates' => array(),
	'home_url' => 'https://example.test', 'wp_version' => '6.6.2', 'http_log' => array(), 'output' => '',
	'redirect' => null, 'died' => null );
register_shutdown_function( function () use ( $state_file ) {
	$GLOBALS['H']['output'] .= ob_get_clean();
	file_put_contents( $state_file, json_encode( $GLOBALS['H'], JSON_PRETTY_PRINT ) );
} );
ob_start();

define( 'ABSPATH', rtrim( getenv( 'HARNESS_WP_DIR' ) ?: sys_get_temp_dir() . '/patchwarden-harness-wp', '/' ) . '/' );
if ( getenv( 'PATCHWARDEN_API_URL' ) ) {
	define( 'PATCHWARDEN_API_URL', getenv( 'PATCHWARDEN_API_URL' ) );
}

// --- hooks -----------------------------------------------------------------------
$GLOBALS['hooks'] = array();
function add_action( $hook, $cb ) { $GLOBALS['hooks'][ $hook ][] = $cb; }
function add_filter( $hook, $cb ) { add_action( $hook, $cb ); }
function do_action( $hook, ...$args ) { foreach ( $GLOBALS['hooks'][ $hook ] ?? array() as $cb ) { $cb( ...$args ); } }
function register_activation_hook( $file, $cb ) { add_action( 'activate_plugin', $cb ); }
function register_deactivation_hook( $file, $cb ) { add_action( 'deactivate_plugin', $cb ); }

// --- options and transients ------------------------------------------------------
function get_option( $name, $default = false ) { return array_key_exists( $name, $GLOBALS['H']['options'] ) ? $GLOBALS['H']['options'][ $name ] : $default; }
function update_option( $name, $value, $autoload = null ) { $GLOBALS['H']['options'][ $name ] = $value; return true; }
function add_option( $name, $value ) { return update_option( $name, $value ); }
function delete_option( $name ) { unset( $GLOBALS['H']['options'][ $name ] ); return true; }
function get_site_transient( $name ) {
	$v = $GLOBALS['H']['site_transients'][ $name ] ?? false;
	if ( ! $v ) { return false; }
	// Same shape as WordPress: an object whose ->response is an array, keyed by plugin file
	// (each entry an object) or by theme stylesheet (each entry an array).
	$t           = new stdClass();
	$t->response = array();
	foreach ( $v['response'] ?? array() as $k => $entry ) {
		$t->response[ $k ] = ( 'update_plugins' === $name ) ? (object) $entry : (array) $entry;
	}
	return $t;
}

// --- cron ------------------------------------------------------------------------
function wp_next_scheduled( $hook ) { return $GLOBALS['H']['cron'][ $hook ]['time'] ?? false; }
function wp_schedule_event( $time, $recurrence, $hook ) { $GLOBALS['H']['cron'][ $hook ] = array( 'time' => $time, 'recurrence' => $recurrence ); return true; }
function wp_clear_scheduled_hook( $hook ) { unset( $GLOBALS['H']['cron'][ $hook ] ); return 0; }

// --- errors ----------------------------------------------------------------------
class WP_Error {
	private $code; private $message;
	public function __construct( $code = '', $message = '' ) { $this->code = $code; $this->message = $message; }
	public function get_error_message() { return $this->message; }
	public function get_error_code() { return $this->code; }
}
function is_wp_error( $thing ) { return $thing instanceof WP_Error; }
function wp_die( $message = '' ) { $GLOBALS['H']['died'] = $message; exit; }

// --- HTTP: really calls the Patchwarden server under test --------------------------
function wp_remote_request( $url, $args = array() ) {
	$ch      = curl_init( $url );
	$headers = array();
	foreach ( $args['headers'] ?? array() as $k => $v ) { $headers[] = "$k: $v"; }
	curl_setopt_array( $ch, array( CURLOPT_CUSTOMREQUEST => $args['method'] ?? 'GET', CURLOPT_RETURNTRANSFER => true,
		CURLOPT_HTTPHEADER => $headers, CURLOPT_TIMEOUT => $args['timeout'] ?? 5, CURLOPT_FOLLOWLOCATION => false ) );
	if ( isset( $args['body'] ) ) { curl_setopt( $ch, CURLOPT_POSTFIELDS, $args['body'] ); }
	$body = curl_exec( $ch );
	$code = (int) curl_getinfo( $ch, CURLINFO_RESPONSE_CODE );
	$GLOBALS['H']['http_log'][] = array( 'method' => $args['method'] ?? 'GET', 'url' => $url, 'status' => $code,
		'sent_key_header' => isset( $args['headers']['X-Patchwarden-Key'] ) );
	if ( false === $body ) { return new WP_Error( 'http_request_failed', curl_error( $ch ) ); }
	return array( 'response' => array( 'code' => $code ), 'body' => $body );
}
function wp_remote_retrieve_response_code( $r ) { return $r['response']['code'] ?? 0; }
function wp_remote_retrieve_body( $r ) { return $r['body'] ?? ''; }
function wp_json_encode( $data ) { return json_encode( $data ); }

// --- plugins, themes, site -------------------------------------------------------
function get_plugins() { return $GLOBALS['H']['plugins']; }
function is_plugin_active( $file ) { return in_array( $file, $GLOBALS['H']['active_plugins'], true ); }
function wp_clean_plugins_cache() {}
function wp_clean_themes_cache() {}
class WP_Theme {
	private $slug;
	public function __construct( $slug ) { $this->slug = $slug; }
	public function get( $field ) { return $GLOBALS['H']['themes'][ $this->slug ][ $field ] ?? ''; }
	public function exists() { return isset( $GLOBALS['H']['themes'][ $this->slug ] ); }
}
function wp_get_themes() { $out = array(); foreach ( array_keys( $GLOBALS['H']['themes'] ) as $s ) { $out[ $s ] = new WP_Theme( $s ); } return $out; }
function wp_get_theme( $slug ) { return new WP_Theme( $slug ); }
function get_stylesheet() { return $GLOBALS['H']['stylesheet']; }
function home_url() { return $GLOBALS['H']['home_url']; }
function get_bloginfo( $what ) { return 'version' === $what ? $GLOBALS['H']['wp_version'] : ''; }
function admin_url( $path = '' ) { return $GLOBALS['H']['home_url'] . '/wp-admin/' . $path; }
function untrailingslashit( $s ) { return rtrim( $s, '/\\' ); }
function wp_parse_url( $url, $component = -1 ) { return parse_url( $url, $component ); }
function absint( $n ) { return abs( (int) $n ); }
function sanitize_key( $k ) { return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( $k ) ); }
function sanitize_text_field( $s ) { return trim( preg_replace( '/[\r\n\t ]+/', ' ', strip_tags( (string) $s ) ) ); }
function wp_unslash( $s ) { return stripslashes( $s ); }
function __( $s, $domain = '' ) { return $s; }
function esc_html( $s ) { return htmlspecialchars( (string) $s, ENT_QUOTES ); }
function esc_attr( $s ) { return esc_html( $s ); }
function esc_url( $s ) { return esc_html( $s ); }
function esc_html__( $s, $domain = '' ) { return esc_html( $s ); }
function current_user_can( $cap ) { return (bool) getenv( 'HARNESS_ADMIN' ); }
function add_options_page( ...$args ) { $GLOBALS['H']['options_page'] = $args[4]; }
function wp_nonce_field( $action ) { echo '<input type="hidden" name="_wpnonce" value="nonce-' . esc_attr( $action ) . '">'; }
function check_admin_referer( $action ) {
	if ( ( $_POST['_wpnonce'] ?? '' ) !== 'nonce-' . $action ) { wp_die( 'The link you followed has expired.' ); }
	return 1;
}
function submit_button( $text ) { echo '<button type="submit">' . esc_html( $text ) . '</button>'; }
function wp_safe_redirect( $url ) { $GLOBALS['H']['redirect'] = $url; return true; }

// --- upgraders: "download" the update the harness says is available ---------------
class Automatic_Upgrader_Skin {}
class Plugin_Upgrader {
	public function __construct( $skin ) {}
	public function upgrade( $file ) {
		$to = $GLOBALS['H']['available_updates'][ $file ] ?? null;
		if ( ! $to ) { return new WP_Error( 'up_to_date', 'The plugin is at the latest version.' ); }
		$GLOBALS['H']['plugins'][ $file ]['Version'] = $to;
		unset( $GLOBALS['H']['available_updates'][ $file ] );
		return true;
	}
}
class Theme_Upgrader {
	public function __construct( $skin ) {}
	public function upgrade( $slug ) {
		$to = $GLOBALS['H']['available_updates'][ 'theme:' . $slug ] ?? null;
		if ( ! $to ) { return new WP_Error( 'up_to_date', 'The theme is at the latest version.' ); }
		$GLOBALS['H']['themes'][ $slug ]['Version'] = $to;
		return true;
	}
}
// WordPress files the plugin require_once's: empty stand-ins.
@mkdir( ABSPATH . 'wp-admin/includes', 0777, true );
foreach ( array( 'plugin.php', 'class-wp-upgrader.php' ) as $f ) {
	if ( ! file_exists( ABSPATH . 'wp-admin/includes/' . $f ) ) { file_put_contents( ABSPATH . 'wp-admin/includes/' . $f, "<?php\n" ); }
}

// --- run -------------------------------------------------------------------------
$plugin_dir = getenv( 'PATCHWARDEN_PLUGIN_DIR' );
$command    = $argv[1] ?? 'dump';
if ( 'uninstall' === $command ) {
	define( 'WP_UNINSTALL_PLUGIN', 'patchwarden/patchwarden.php' );
	require $plugin_dir . '/uninstall.php';
	exit;
}
require $plugin_dir . '/patchwarden.php';
switch ( $command ) {
	case 'activate':
		do_action( 'activate_plugin' );
		break;
	case 'deactivate':
		do_action( 'deactivate_plugin' );
		break;
	case 'save_key':
		$_POST = array( 'action' => 'patchwarden_save_key', '_wpnonce' => $argv[3] ?? 'nonce-patchwarden_save_key',
			'patchwarden_api_key' => $argv[2] ?? '' );
		do_action( 'admin_post_patchwarden_save_key' );
		break;
	case 'cron':
		if ( ! wp_next_scheduled( $argv[2] ) ) { $GLOBALS['H']['died'] = 'not scheduled: ' . $argv[2]; break; }
		do_action( $argv[2] );
		break;
	case 'settings_page':
		do_action( 'admin_menu' );
		call_user_func( $GLOBALS['H']['options_page'] );
		break;
}
