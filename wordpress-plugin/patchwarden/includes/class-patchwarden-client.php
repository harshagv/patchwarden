<?php
/**
 * Talks to Patchwarden. Outbound only: Patchwarden never connects into this site.
 *
 * @package Patchwarden
 */

defined( 'ABSPATH' ) || exit;

/**
 * A small HTTPS client for the Patchwarden API.
 */
class Patchwarden_Client {

	/**
	 * API base URL.
	 *
	 * @var string
	 */
	private $base;

	/**
	 * The site's API key.
	 *
	 * @var string
	 */
	private $key;

	/**
	 * Constructor.
	 *
	 * @param string $base API base URL.
	 * @param string $key  API key.
	 */
	public function __construct( $base, $key ) {
		$this->base = untrailingslashit( $base );
		$this->key  = $key;
	}

	/**
	 * A client from the saved key and the configured address, or a WP_Error saying what is missing.
	 *
	 * @return Patchwarden_Client|WP_Error
	 */
	public static function from_options() {
		$key = get_option( PATCHWARDEN_OPTION_KEY, '' );
		if ( ! is_string( $key ) || '' === $key ) {
			return new WP_Error( 'patchwarden_no_key', __( 'Paste your Patchwarden key to connect.', 'patchwarden' ) );
		}
		$base   = defined( 'PATCHWARDEN_API_URL' ) ? (string) PATCHWARDEN_API_URL : '';
		$scheme = wp_parse_url( $base, PHP_URL_SCHEME );
		$host   = wp_parse_url( $base, PHP_URL_HOST );
		// HTTPS only, except a Patchwarden running on this same machine (development).
		$local = in_array( $host, array( 'localhost', '127.0.0.1', '::1' ), true );
		if ( 'https' !== $scheme && ! ( 'http' === $scheme && $local ) ) {
			return new WP_Error( 'patchwarden_bad_url', __( 'The Patchwarden address must use https.', 'patchwarden' ) );
		}
		return new self( $base, $key );
	}

	/**
	 * Call the API.
	 *
	 * @param string     $method HTTP method.
	 * @param string     $path   API path.
	 * @param array|null $body   JSON body.
	 * @return array|WP_Error Decoded JSON, or an error with a plain-language message.
	 */
	public function request( $method, $path, $body = null ) {
		$args = array(
			'method'      => $method,
			'timeout'     => 15,
			'redirection' => 0,
			'sslverify'   => true,
			'headers'     => array(
				'X-Patchwarden-Key' => $this->key,
				'Accept'         => 'application/json',
				'Content-Type'   => 'application/json',
			),
		);
		if ( null !== $body ) {
			$args['body'] = wp_json_encode( $body );
		}
		$response = wp_remote_request( $this->base . $path, $args );
		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'patchwarden_unreachable', __( 'Could not reach Patchwarden. We will try again later.', 'patchwarden' ) );
		}
		$code = (int) wp_remote_retrieve_response_code( $response );
		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( $code < 200 || $code >= 300 ) {
			$message = ( is_array( $data ) && ! empty( $data['message'] ) ) ? (string) $data['message'] : 'Patchwarden answered ' . $code . '.';
			return new WP_Error( 'patchwarden_http_' . $code, $message );
		}
		return is_array( $data ) ? $data : array();
	}
}
