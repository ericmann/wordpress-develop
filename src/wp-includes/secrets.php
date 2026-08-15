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
