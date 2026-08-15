<?php
/**
 * Secrets API: WP_Secrets_Option_Store class.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Default Secrets API storage backend, using core's options tables.
 *
 * Site-level records are stored as `_wp_secret_{name}` options with
 * autoload disabled. Network-level records are stored as
 * `_wp_network_secret_{name}` network meta in `wp_sitemeta`.
 *
 * @since 7.2.0
 */
class WP_Secrets_Option_Store implements WP_Secrets_Store {

	/**
	 * Option name prefix for site-level secret records.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const SITE_PREFIX = '_wp_secret_';

	/**
	 * Network meta key prefix for network-level secret records.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const NETWORK_PREFIX = '_wp_network_secret_';

	/**
	 * Retrieves a stored secret record.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param bool   $network Optional. Default false.
	 * @return string|null Raw record JSON, or null if the name does not exist.
	 */
	public function get( $name, $network = false ) {
		$option_name = $this->option_name( $name, $network );
		$value       = $network ? get_site_option( $option_name ) : get_option( $option_name );

		return false === $value ? null : $value;
	}

	/**
	 * Persists a secret record.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param string $record  Raw record JSON.
	 * @param bool   $network Optional. Default false.
	 * @return true
	 */
	public function set( $name, $record, $network = false ) {
		$option_name = $this->option_name( $name, $network );

		if ( $network ) {
			update_site_option( $option_name, $record );
		} else {
			update_option( $option_name, $record, false );
		}

		return true;
	}

	/**
	 * Deletes a stored secret record.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param bool   $network Optional. Default false.
	 * @return true
	 */
	public function delete( $name, $network = false ) {
		$option_name = $this->option_name( $name, $network );

		if ( $network ) {
			delete_site_option( $option_name );
		} else {
			delete_option( $option_name );
		}

		return true;
	}

	/**
	 * Lists the names of all stored secrets.
	 *
	 * The `_` in both prefixes is a `LIKE` wildcard matching any single
	 * character, so it must be escaped with `esc_like()`. Left
	 * unescaped, the site-level prefix `_wp_secret_` would also match
	 * `_wp_secrets_master_key` (the wrapped master key option): the
	 * trailing underscore wildcard-matches the "s" that begins
	 * "secrets", and prefix matching does the rest.
	 *
	 * @since 7.2.0
	 *
	 * @global wpdb $wpdb WordPress database abstraction object.
	 *
	 * @param bool $network Optional. Default false.
	 * @return string[] Names only, never values.
	 */
	public function list_names( $network = false ) {
		global $wpdb;

		$prefix = $network ? self::NETWORK_PREFIX : self::SITE_PREFIX;
		$like   = $wpdb->esc_like( $prefix ) . '%';

		if ( $network ) {
			$rows = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT meta_key FROM {$wpdb->sitemeta} WHERE meta_key LIKE %s AND site_id = %d",
					$like,
					get_current_network_id()
				)
			);
		} else {
			$rows = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
					$like
				)
			);
		}

		$prefix_length = strlen( $prefix );

		return array_map(
			function ( $row ) use ( $prefix_length ) {
				return substr( $row, $prefix_length );
			},
			$rows
		);
	}

	/**
	 * Builds the storage key for a secret name.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param bool   $network Whether this is a network-level secret.
	 * @return string The option name or network meta key.
	 */
	private function option_name( $name, $network ) {
		return ( $network ? self::NETWORK_PREFIX : self::SITE_PREFIX ) . $name;
	}
}
