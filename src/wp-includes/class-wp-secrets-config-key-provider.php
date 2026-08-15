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
 * The site key wraps the per-site master key. It is resolved from the
 * `WP_SECRETS_KEY` constant, if defined.
 *
 * @since 7.2.0
 */
class WP_Secrets_Config_Key_Provider {

	/**
	 * Resolves the site key.
	 *
	 * @since 7.2.0
	 *
	 * @return string|WP_Error 32 raw bytes, or WP_Error if no usable key
	 *                         is currently configured.
	 */
	public function get_site_key() {
		if ( defined( 'WP_SECRETS_KEY' ) ) {
			return $this->decode_constant( WP_SECRETS_KEY );
		}

		return new WP_Error( 'secret_key_provider_unavailable', __( 'No Secrets API site key is configured.' ) );
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
}
