<?php
/**
 * Secrets API: WP_Secrets_Store interface.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Storage backend contract for the Secrets API.
 *
 * The store only ever receives ciphertext: it is handed the record JSON
 * (§4.3), which contains no plaintext. Implementations must fail closed
 * - a WP_Error from any method propagates to the caller unchanged, with
 * no fallback to a default implementation.
 *
 * Core's default, WP_Secrets_Option_Store, is used when
 * `$GLOBALS['wp_secrets_store']` is unset. A `secrets.php` drop-in may
 * replace it with an implementation backed by an external vault.
 *
 * @since 7.2.0
 */
interface WP_Secrets_Store {

	/**
	 * Retrieves a stored secret record.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param bool   $network Optional. Whether to operate on the network
	 *                        keyspace rather than the site keyspace.
	 *                        Default false.
	 * @return string|null|WP_Error Raw record JSON, null if the name does
	 *                              not exist, WP_Error if the store is
	 *                              unreachable.
	 */
	public function get( $name, $network = false );

	/**
	 * Persists a secret record.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param string $record  Raw record JSON.
	 * @param bool   $network Optional. Whether to operate on the network
	 *                        keyspace rather than the site keyspace.
	 *                        Default false.
	 * @return true|WP_Error
	 */
	public function set( $name, $record, $network = false );

	/**
	 * Deletes a stored secret record.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param bool   $network Optional. Whether to operate on the network
	 *                        keyspace rather than the site keyspace.
	 *                        Default false.
	 * @return true|WP_Error
	 */
	public function delete( $name, $network = false );

	/**
	 * Lists the names of all stored secrets.
	 *
	 * @since 7.2.0
	 *
	 * @param bool $network Optional. Whether to operate on the network
	 *                       keyspace rather than the site keyspace.
	 *                       Default false.
	 * @return string[]|WP_Error Names only, never values.
	 */
	public function list_names( $network = false );
}
