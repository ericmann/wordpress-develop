<?php
/**
 * Core Secrets API.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

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
 * Resolves the site ID a site-level secret's AAD should be bound to.
 *
 * @since 7.2.0
 *
 * @return int The current blog ID on multisite, 1 otherwise.
 */
function wp_secrets_current_site_id() {
	return is_multisite() ? get_current_blog_id() : 1;
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
	$valid_name = wp_secrets_validate_name( $name );

	if ( is_wp_error( $valid_name ) ) {
		return $valid_name;
	}

	if ( ! is_string( $value ) || '' === $value ) {
		return new WP_Error( 'secret_empty_value', __( 'Secret values must be non-empty strings.' ) );
	}

	$master_key = ( new WP_Secrets_Key_Manager() )->get_master_key();

	if ( is_wp_error( $master_key ) ) {
		return $master_key;
	}

	$store   = new WP_Secrets_Option_Store();
	$cipher  = new WP_Secrets_Cipher();
	$site_id = wp_secrets_current_site_id();

	$previous_slot = wp_secrets_demote_current_slot( $store->get( $name ), $master_key, $cipher, $name, $site_id );

	if ( is_wp_error( $previous_slot ) ) {
		return $previous_slot;
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

	$store->set( $name, wp_json_encode( $record ) );

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
	$valid_name = wp_secrets_validate_name( $name );

	if ( is_wp_error( $valid_name ) ) {
		return $valid_name;
	}

	$raw = ( new WP_Secrets_Option_Store() )->get( $name );

	if ( is_wp_error( $raw ) || null === $raw ) {
		return $raw;
	}

	$record = json_decode( $raw, true );

	if ( ! is_array( $record ) || 1 !== ( isset( $record['v'] ) ? $record['v'] : null )
		|| ! isset( $record['current']['ct'], $record['current']['nonce'] )
	) {
		return new WP_Error( 'secret_decryption_failed', __( 'The stored secret record is malformed.' ) );
	}

	$master_key = ( new WP_Secrets_Key_Manager() )->get_master_key();

	if ( is_wp_error( $master_key ) ) {
		return $master_key;
	}

	$plaintext = ( new WP_Secrets_Cipher() )->decrypt(
		$record['current']['ct'],
		$record['current']['nonce'],
		$master_key,
		$name,
		'current',
		wp_secrets_current_site_id()
	);

	if ( is_wp_error( $plaintext ) ) {
		return $plaintext;
	}

	$fingerprint = isset( $record['current']['fp'] ) ? $record['current']['fp'] : '';

	return new WP_Secret( $name, $plaintext, $fingerprint );
}
