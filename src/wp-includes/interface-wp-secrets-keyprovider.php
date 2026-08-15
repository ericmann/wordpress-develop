<?php
/**
 * Secrets API: WP_Secrets_Key_Provider interface.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Key-wrapping backend contract for the Secrets API.
 *
 * The key provider only ever receives the master key (or, on multisite,
 * the network root key), never a secret value. Implementations must
 * fail closed - a WP_Error from either method propagates to the
 * caller unchanged, with no fallback to the default implementation.
 *
 * Core's default, WP_Secrets_Config_Key_Provider, is used when
 * `$GLOBALS['wp_secrets_key_provider']` is unset. A `secrets.php`
 * drop-in may replace it with an implementation backed by an external
 * key management service.
 *
 * @since 7.2.0
 */
interface WP_Secrets_Key_Provider {

	/**
	 * Wraps key material.
	 *
	 * @since 7.2.0
	 *
	 * @param string $key_material 32 raw bytes.
	 * @return string|WP_Error Opaque wrapped form.
	 */
	public function wrap( $key_material );

	/**
	 * Unwraps previously wrapped key material.
	 *
	 * @since 7.2.0
	 *
	 * @param string $wrapped Opaque wrapped form, as previously returned by wrap().
	 * @return string|WP_Error 32 raw bytes.
	 */
	public function unwrap( $wrapped );
}
