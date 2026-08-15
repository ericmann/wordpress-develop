<?php
/**
 * Core Secrets API.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Checks whether an option name belongs to the Secrets API's reserved
 * storage namespace.
 *
 * Secrets API storage (`_wp_secret_*` records, `_wp_secrets_*` internals
 * like the wrapped master key) must never appear on a disclosure
 * surface: the All Options screen, REST settings, or an export. This is
 * the single predicate every such surface should consult.
 *
 * @since 7.2.0
 *
 * @param string $option_name The option name to check.
 * @return bool
 */
function wp_secrets_is_reserved_option_name( $option_name ) {
	return is_string( $option_name ) && (
		str_starts_with( $option_name, '_wp_secret_' ) ||
		str_starts_with( $option_name, '_wp_secrets_' )
	);
}

/**
 * Validates a Secrets API name against the naming grammar.
 *
 * Names take the form `namespace/name`, where both segments match
 * `[a-z0-9]([a-z0-9_-]*[a-z0-9])?`. There must be exactly one `/`, and the
 * total length must not exceed 160 bytes (the `option_name` column is
 * `varchar(191)` and the storage prefix consumes 11 of those bytes).
 *
 * Invalid names are rejected rather than normalized. Silently lowercasing
 * or trimming a name would let two different callers collide on the same
 * stored record without either of them knowing it happened.
 *
 * @since 7.2.0
 *
 * @param string $name Namespaced secret name, e.g. 'plugin-slug/secret-name'.
 * @return true|WP_Error True if the name is valid, WP_Error otherwise.
 */
function wp_secrets_validate_name( $name ) {
	if ( ! is_string( $name ) || '' === $name ) {
		return new WP_Error( 'secret_invalid_name', __( 'Secret names must be non-empty strings.' ) );
	}

	if ( strlen( $name ) > 160 ) {
		return new WP_Error( 'secret_invalid_name', __( 'Secret names must not exceed 160 bytes.' ) );
	}

	$segment = '[a-z0-9]([a-z0-9_-]*[a-z0-9])?';

	if ( ! preg_match( '/^' . $segment . '\/' . $segment . '$/', $name ) ) {
		return new WP_Error( 'secret_invalid_name', __( 'Secret names must take the form &#8216;namespace/name&#8217;, with each segment being lowercase alphanumeric characters optionally separated by hyphens or underscores.' ) );
	}

	return true;
}

/**
 * Best-effort zeroing of a string containing sensitive data.
 *
 * Prefers the `sodium_memzero()` extension function, which wipes the
 * underlying buffer in place. That function throws a `SodiumException`
 * when ext-sodium is not loaded, because sodium_compat defines the
 * related constants but cannot implement it as a userland polyfill, so
 * it is never called unless the real extension is present.
 *
 * When ext-sodium is unavailable, the fallback overwrites the variable
 * with null bytes. This is best-effort only: PHP's copy-on-write
 * semantics mean earlier copies of the string may already exist
 * elsewhere in memory. Callers must not treat this as a guarantee of
 * erasure.
 *
 * @since 7.2.0
 *
 * @param string $value String to zero, by reference.
 */
function wp_secrets_memzero( &$value ) {
	if ( function_exists( 'sodium_memzero' ) && extension_loaded( 'sodium' ) ) {
		sodium_memzero( $value );
		return;
	}

	$value = str_repeat( "\0", strlen( $value ) );
}

/**
 * Resolves the ID a secret's AAD should be bound to.
 *
 * @since 7.2.0
 *
 * @param bool $network Optional. Whether to resolve the network keyspace's
 *                       ID rather than the site's. Default false.
 * @return int For a site-level secret, the current blog ID on multisite,
 *             1 otherwise. For a network-level secret, the current
 *             network ID.
 */
function wp_secrets_current_site_id( $network = false ) {
	if ( $network ) {
		return get_current_network_id();
	}

	return is_multisite() ? get_current_blog_id() : 1;
}

/**
 * Resolves the master key used to encrypt site-level or network-level secrets.
 *
 * On a single-site install, or for the network keyspace, this is a
 * random 32-byte key generated once and wrapped under the site key
 * (see WP_Secrets_Key_Manager).
 *
 * On multisite, a site's master key is instead derived from the
 * network root key and the site's own ID:
 * `crypto_kdf_derive_from_key(32, $site_id, "wpsecret", $network_root_key)`.
 * A network of 500 sites then has one wrapped key to rotate, not 500:
 * rotating `WP_SECRETS_KEY` re-wraps the network root key once, and
 * every site's derived master key is unchanged, because the network
 * root key's raw bytes never change - only their wrapping does.
 *
 * @since 7.2.0
 * @access private
 *
 * @param bool $network Optional. Whether to resolve the network's own
 *                       master key rather than a site's. Default false.
 * @return string|WP_Error 32 raw bytes, or WP_Error.
 */
function wp_secrets_resolve_master_key( $network = false ) {
	if ( $network ) {
		return ( new WP_Secrets_Key_Manager( null, true ) )->get_master_key();
	}

	if ( ! is_multisite() ) {
		return ( new WP_Secrets_Key_Manager() )->get_master_key();
	}

	$network_root_key = ( new WP_Secrets_Key_Manager( null, true ) )->get_master_key();

	if ( is_wp_error( $network_root_key ) ) {
		return $network_root_key;
	}

	$site_master_key = sodium_crypto_kdf_derive_from_key( 32, get_current_blog_id(), 'wpsecret', $network_root_key );

	wp_secrets_memzero( $network_root_key );

	return $site_master_key;
}

/**
 * Sets a secret's value, creating or overwriting it.
 *
 * Encryption is always on: there is no configuration, constant, filter,
 * or drop-in that disables it.
 *
 * Overwriting an existing secret demotes its current value to the
 * previous slot, discarding whatever was already there. There are
 * exactly two slots; named version history is out of scope. Keeping
 * every credential a site has ever held recoverable from a backup
 * indefinitely would work against the entire reason anyone rotates.
 *
 * @since 7.2.0
 *
 * @param string $name  Namespaced secret name: 'plugin-slug/secret-name'.
 * @param string $value Plaintext. Non-empty.
 * @return true|WP_Error True on success, WP_Error otherwise.
 */
function wp_set_secret( $name, $value ) {
	return _wp_secrets_set( $name, $value, false );
}

/**
 * Sets a network-level secret's value, creating or overwriting it.
 *
 * On a single-site install this proxies directly to wp_set_secret():
 * there is no separate network keyspace to speak of. On multisite it
 * operates on the network keyspace instead of the current site's -
 * there is no implicit fallback between the two in either direction.
 *
 * @since 7.2.0
 *
 * @param string $name  Namespaced secret name: 'plugin-slug/secret-name'.
 * @param string $value Plaintext. Non-empty.
 * @return true|WP_Error True on success, WP_Error otherwise.
 */
function wp_set_network_secret( $name, $value ) {
	if ( ! is_multisite() ) {
		return wp_set_secret( $name, $value );
	}

	return _wp_secrets_set( $name, $value, true );
}

/**
 * Implementation shared by wp_set_secret() and wp_set_network_secret().
 *
 * @since 7.2.0
 * @access private
 *
 * @param string $name    Namespaced secret name.
 * @param string $value   Plaintext. Non-empty.
 * @param bool   $network Whether to operate on the network keyspace.
 * @return true|WP_Error True on success, WP_Error otherwise.
 */
function _wp_secrets_set( $name, $value, $network ) {
	$valid_name = wp_secrets_validate_name( $name );

	if ( is_wp_error( $valid_name ) ) {
		return $valid_name;
	}

	if ( ! is_string( $value ) || '' === $value ) {
		return new WP_Error( 'secret_empty_value', __( 'Secret values must be non-empty strings.' ) );
	}

	$master_key = wp_secrets_resolve_master_key( $network );

	if ( is_wp_error( $master_key ) ) {
		return $master_key;
	}

	$store    = new WP_Secrets_Option_Store();
	$cipher   = new WP_Secrets_Cipher();
	$site_id  = wp_secrets_current_site_id( $network );
	$existing = $store->get( $name, $network );

	$previous_slot = wp_secrets_demote_current_slot( $existing, $master_key, $cipher, $name, $site_id );

	if ( is_wp_error( $previous_slot ) ) {
		return $previous_slot;
	}

	$existing_record = is_string( $existing ) ? json_decode( $existing, true ) : null;
	$old_fingerprint = isset( $existing_record['current']['fp'] ) ? $existing_record['current']['fp'] : '';

	if ( null === $existing_record ) {
		$action = 'created';
	} elseif ( ! empty( $existing_record['needs_rotation'] ) ) {
		$action = 'rotated';
	} else {
		$action = 'updated';
	}

	$encrypted   = $cipher->encrypt( $value, $master_key, $name, 'current', $site_id );
	$fingerprint = $cipher->fingerprint( $value, $master_key );
	$now         = time();

	$record = array(
		'v'              => 1,
		'current'        => array(
			'ct'      => $encrypted['ct'],
			'nonce'   => $encrypted['nonce'],
			'fp'      => $fingerprint,
			'created' => $now,
		),
		'previous'       => $previous_slot,
		'needs_rotation' => false,
		'updated'        => $now,
	);

	$store->set( $name, wp_json_encode( $record ), $network );

	/**
	 * Fires when a secret is created, updated, rotated, or deleted.
	 *
	 * This is a write-side signal only: it carries fingerprints, never
	 * values. Nothing about the arguments passed to a listener on this
	 * hook can be used to recover a secret's plaintext.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name             Namespaced secret name.
	 * @param string $action           'created', 'updated', 'rotated', or 'deleted'.
	 * @param int    $actor_id         ID of the user who made the change, 0 if none.
	 * @param int    $timestamp        Unix timestamp of the change.
	 * @param string $old_fingerprint  The previous value's fingerprint, '' when there was none.
	 * @param string $new_fingerprint  The new value's fingerprint, '' on delete.
	 */
	do_action( 'wp_secret_changed', $name, $action, get_current_user_id(), $now, $old_fingerprint, $fingerprint );

	return true;
}

/**
 * Re-encrypts an existing record's current slot for the previous slot.
 *
 * The AAD binds a slot's ciphertext to its position, so the old current
 * slot cannot simply be copied into previous: it must be decrypted and
 * re-encrypted under the previous slot's own AAD.
 *
 * @since 7.2.0
 * @access private
 *
 * @param string|null|WP_Error $existing   The existing raw record JSON, as
 *                                         returned by a WP_Secrets_Store.
 * @param string               $master_key 32 raw bytes.
 * @param WP_Secrets_Cipher    $cipher     Cipher instance to use.
 * @param string               $name       Namespaced secret name.
 * @param int                  $site_id    Site ID the secret belongs to.
 * @return array|null|WP_Error The new previous slot, null if there was no
 *                             existing current slot to demote, or
 *                             WP_Error if the existing slot exists but
 *                             cannot be decrypted.
 */
function wp_secrets_demote_current_slot( $existing, $master_key, WP_Secrets_Cipher $cipher, $name, $site_id ) {
	if ( is_wp_error( $existing ) ) {
		return $existing;
	}

	if ( ! is_string( $existing ) ) {
		return null;
	}

	$existing_record = json_decode( $existing, true );

	if ( ! is_array( $existing_record ) || empty( $existing_record['current']['ct'] ) || empty( $existing_record['current']['nonce'] ) ) {
		return null;
	}

	$old_plaintext = $cipher->decrypt( $existing_record['current']['ct'], $existing_record['current']['nonce'], $master_key, $name, 'current', $site_id );

	if ( is_wp_error( $old_plaintext ) ) {
		return $old_plaintext;
	}

	$re_encrypted = $cipher->encrypt( $old_plaintext, $master_key, $name, 'previous', $site_id );

	wp_secrets_memzero( $old_plaintext );

	return array(
		'ct'      => $re_encrypted['ct'],
		'nonce'   => $re_encrypted['nonce'],
		'fp'      => $existing_record['current']['fp'],
		'created' => $existing_record['current']['created'],
	);
}

/**
 * Retrieves a secret's value.
 *
 * @since 7.2.0
 *
 * @param string $name Namespaced secret name.
 * @return WP_Secret|null|WP_Error WP_Secret if it exists and decrypts,
 *                                 null if it does not exist, WP_Error if
 *                                 it exists but does not decrypt.
 */
function wp_get_secret( $name ) {
	return _wp_secrets_get( $name, false );
}

/**
 * Retrieves a network-level secret's value.
 *
 * On a single-site install this proxies directly to wp_get_secret().
 * On multisite it operates on the network keyspace only: a secret set
 * with wp_set_secret() is not found here, and vice versa.
 *
 * @since 7.2.0
 *
 * @param string $name Namespaced secret name.
 * @return WP_Secret|null|WP_Error WP_Secret if it exists and decrypts,
 *                                 null if it does not exist, WP_Error if
 *                                 it exists but does not decrypt.
 */
function wp_get_network_secret( $name ) {
	if ( ! is_multisite() ) {
		return wp_get_secret( $name );
	}

	return _wp_secrets_get( $name, true );
}

/**
 * Implementation shared by wp_get_secret() and wp_get_network_secret().
 *
 * @since 7.2.0
 * @access private
 *
 * @param string $name    Namespaced secret name.
 * @param bool   $network Whether to operate on the network keyspace.
 * @return WP_Secret|null|WP_Error WP_Secret if it exists and decrypts,
 *                                 null if it does not exist, WP_Error if
 *                                 it exists but does not decrypt.
 */
function _wp_secrets_get( $name, $network ) {
	$valid_name = wp_secrets_validate_name( $name );

	if ( is_wp_error( $valid_name ) ) {
		return $valid_name;
	}

	$raw = ( new WP_Secrets_Option_Store() )->get( $name, $network );

	if ( is_wp_error( $raw ) || null === $raw ) {
		return $raw;
	}

	$record = json_decode( $raw, true );

	if ( ! is_array( $record ) || 1 !== ( isset( $record['v'] ) ? $record['v'] : null )
		|| ! isset( $record['current']['ct'], $record['current']['nonce'] )
	) {
		return new WP_Error( 'secret_decryption_failed', __( 'The stored secret record is malformed.' ) );
	}

	$master_key = wp_secrets_resolve_master_key( $network );

	if ( is_wp_error( $master_key ) ) {
		return $master_key;
	}

	$plaintext = ( new WP_Secrets_Cipher() )->decrypt(
		$record['current']['ct'],
		$record['current']['nonce'],
		$master_key,
		$name,
		'current',
		wp_secrets_current_site_id( $network )
	);

	if ( is_wp_error( $plaintext ) ) {
		return $plaintext;
	}

	$fingerprint = isset( $record['current']['fp'] ) ? $record['current']['fp'] : '';

	return new WP_Secret( $name, $plaintext, $fingerprint );
}

/**
 * Deletes a secret.
 *
 * Removes the entire stored record, current and previous slots alike:
 * there is only one record per name, so there is nothing partial to
 * leave behind.
 *
 * @since 7.2.0
 *
 * @param string $name Namespaced secret name.
 * @return true|WP_Error True on success, WP_Error if it did not exist.
 */
function wp_delete_secret( $name ) {
	return _wp_secrets_delete( $name, false );
}

/**
 * Deletes a network-level secret.
 *
 * On a single-site install this proxies directly to
 * wp_delete_secret(). On multisite it operates on the network
 * keyspace only.
 *
 * @since 7.2.0
 *
 * @param string $name Namespaced secret name.
 * @return true|WP_Error True on success, WP_Error if it did not exist.
 */
function wp_delete_network_secret( $name ) {
	if ( ! is_multisite() ) {
		return wp_delete_secret( $name );
	}

	return _wp_secrets_delete( $name, true );
}

/**
 * Implementation shared by wp_delete_secret() and wp_delete_network_secret().
 *
 * @since 7.2.0
 * @access private
 *
 * @param string $name    Namespaced secret name.
 * @param bool   $network Whether to operate on the network keyspace.
 * @return true|WP_Error True on success, WP_Error if it did not exist.
 */
function _wp_secrets_delete( $name, $network ) {
	$valid_name = wp_secrets_validate_name( $name );

	if ( is_wp_error( $valid_name ) ) {
		return $valid_name;
	}

	$store    = new WP_Secrets_Option_Store();
	$existing = $store->get( $name, $network );

	if ( is_wp_error( $existing ) ) {
		return $existing;
	}

	if ( null === $existing ) {
		return new WP_Error( 'secret_not_found', __( 'This secret does not exist.' ) );
	}

	$deleted = $store->delete( $name, $network );

	if ( is_wp_error( $deleted ) ) {
		return $deleted;
	}

	$existing_record = json_decode( $existing, true );
	$old_fingerprint = isset( $existing_record['current']['fp'] ) ? $existing_record['current']['fp'] : '';

	/** This action is documented in wp-includes/secrets.php */
	do_action( 'wp_secret_changed', $name, 'deleted', get_current_user_id(), time(), $old_fingerprint, '' );

	return true;
}

/**
 * Lists metadata for stored secrets. Never values.
 *
 * @since 7.2.0
 *
 * @param string $namespace Optional. Restrict results to one namespace.
 *                          Default '' (all namespaces).
 * @return array[]|WP_Error Each entry: name, fingerprint,
 *                          previous_fingerprint, created, updated,
 *                          needs_rotation.
 */
function wp_list_secrets( $namespace = '' ) { // phpcs:ignore Universal.NamingConventions.NoReservedKeywordParameterNames.namespaceFound
	return _wp_secrets_list( $namespace, false );
}

/**
 * Lists metadata for stored network-level secrets. Never values.
 *
 * On a single-site install this proxies directly to
 * wp_list_secrets(). On multisite it operates on the network keyspace
 * only.
 *
 * @since 7.2.0
 *
 * @param string $namespace Optional. Restrict results to one namespace.
 *                          Default '' (all namespaces).
 * @return array[]|WP_Error Each entry: name, fingerprint,
 *                          previous_fingerprint, created, updated,
 *                          needs_rotation.
 */
function wp_list_network_secrets( $namespace = '' ) { // phpcs:ignore Universal.NamingConventions.NoReservedKeywordParameterNames.namespaceFound
	if ( ! is_multisite() ) {
		return wp_list_secrets( $namespace );
	}

	return _wp_secrets_list( $namespace, true );
}

/**
 * Implementation shared by wp_list_secrets() and wp_list_network_secrets().
 *
 * @since 7.2.0
 * @access private
 *
 * @param string $namespace Restrict results to one namespace, '' for all.
 * @param bool   $network   Whether to operate on the network keyspace.
 * @return array[]|WP_Error Each entry: name, fingerprint,
 *                          previous_fingerprint, created, updated,
 *                          needs_rotation.
 */
function _wp_secrets_list( $namespace, $network ) { // phpcs:ignore Universal.NamingConventions.NoReservedKeywordParameterNames.namespaceFound
	$store = new WP_Secrets_Option_Store();
	$names = $store->list_names( $network );

	if ( is_wp_error( $names ) ) {
		return $names;
	}

	$prefix  = '' === $namespace ? '' : $namespace . '/';
	$results = array();

	foreach ( $names as $name ) {
		if ( '' !== $prefix && 0 !== strpos( $name, $prefix ) ) {
			continue;
		}

		$raw = $store->get( $name, $network );

		if ( is_wp_error( $raw ) || null === $raw ) {
			continue;
		}

		$record = json_decode( $raw, true );

		if ( ! is_array( $record ) ) {
			continue;
		}

		$results[] = array(
			'name'                 => $name,
			'fingerprint'          => isset( $record['current']['fp'] ) ? $record['current']['fp'] : '',
			'previous_fingerprint' => isset( $record['previous']['fp'] ) ? $record['previous']['fp'] : '',
			'created'              => isset( $record['current']['created'] ) ? $record['current']['created'] : null,
			'updated'              => isset( $record['updated'] ) ? $record['updated'] : null,
			'needs_rotation'       => ! empty( $record['needs_rotation'] ),
		);
	}

	return $results;
}
