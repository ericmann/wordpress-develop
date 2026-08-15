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
