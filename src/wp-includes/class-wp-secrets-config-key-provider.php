<?php
/**
 * Secrets API: WP_Secrets_Config_Key_Provider class.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Resolves the Secrets API site key from local configuration.
 *
 * The site key wraps the per-site master key. It is resolved, in order:
 *
 *  1. The `WP_SECRETS_KEY` constant, if defined: base64-decoded, must be
 *     exactly 32 bytes.
 *  2. Otherwise, derived from `LOGGED_IN_KEY` and `LOGGED_IN_SALT`, which
 *     are already present on every site. This is the same fallback Site
 *     Kit's `Data_Encryption` class uses at scale; it is why rotating
 *     those salts invalidates stored secrets once `WP_SECRETS_KEY` is
 *     undefined: they become load-bearing key material rather than
 *     session-cookie entropy the moment there is nothing else to use.
 *
 * @since 7.2.0
 */
class WP_Secrets_Config_Key_Provider {

	/**
	 * Resolves the site key.
	 *
	 * @since 7.2.0
	 *
	 * @return string|WP_Error 32 raw bytes, or WP_Error if `WP_SECRETS_KEY`
	 *                         is defined but invalid.
	 */
	public function get_site_key() {
		if ( defined( 'WP_SECRETS_KEY' ) ) {
			return $this->decode_constant( WP_SECRETS_KEY );
		}

		return $this->derive_from_salts();
	}

	/**
	 * Decodes and validates the `WP_SECRETS_KEY` constant.
	 *
	 * @since 7.2.0
	 *
	 * @param string $encoded The base64-encoded constant value.
	 * @return string|WP_Error 32 raw bytes, or WP_Error if invalid.
	 */
	private function decode_constant( $encoded ) {
		$decoded = base64_decode( (string) $encoded, true );

		if ( false === $decoded || 32 !== strlen( $decoded ) ) {
			return new WP_Error( 'secret_key_provider_unavailable', __( 'The WP_SECRETS_KEY constant must be exactly 32 bytes, base64-encoded.' ) );
		}

		return $decoded;
	}

	/**
	 * Derives a fallback site key from LOGGED_IN_KEY and LOGGED_IN_SALT.
	 *
	 * @since 7.2.0
	 *
	 * @return string 32 raw bytes.
	 */
	private function derive_from_salts() {
		return sodium_crypto_generichash( LOGGED_IN_KEY . LOGGED_IN_SALT, '', 32 );
	}
}
