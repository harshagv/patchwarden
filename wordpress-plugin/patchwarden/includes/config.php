<?php
/**
 * Where this plugin reports. The zip downloaded from your Patchwarden dashboard replaces this file
 * with your Patchwarden's address. Contains no key or secret.
 *
 * @package Patchwarden
 */

defined( 'ABSPATH' ) || exit;

if ( ! defined( 'PATCHWARDEN_API_URL' ) ) {
	define( 'PATCHWARDEN_API_URL', 'http://localhost:8000' );
}
