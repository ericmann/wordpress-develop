<?php
/**
 * Secrets API: WP_Secrets_Config_Key_Provider class.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Resolves the Secrets API site key from local configuration, and wraps
 * arbitrary key material under it.
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
 * This is core's default WP_Secrets_Key_Provider, used when
 * `$GLOBALS['wp_secrets_key_provider']` is unset. wrap()/unwrap() use
 * only the current site key: WP_Secrets_Key_Manager handles the
 * WP_SECRETS_KEY_PREVIOUS retry-and-rewrap dance itself, via
 * get_site_key()/get_previous_site_key() directly, since that specific
 * rotation mechanism is a property of this config-based provider, not
 * something a drop-in provider necessarily shares.
 *
 * @since 7.2.0
 */
class WP_Secrets_Config_Key_Provider implements WP_Secrets_Key_Provider {

	/**
	 * AAD binding a wrap()/unwrap() call to its purpose.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const WRAP_AAD = 'wp-secrets-key-wrap-v1';

	/**
	 * Wraps key material under the current site key.
	 *
	 * @since 7.2.0
	 *
	 * @param string $key_material 32 raw bytes.
	 * @return string|WP_Error Opaque wrapped form (JSON), or WP_Error if
	 *                         the site key is unavailable.
	 */
	public function wrap( $key_material ) {
		$site_key = $this->get_site_key();

		if ( is_wp_error( $site_key ) ) {
			return $site_key;
		}

		$nonce      = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		$ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( $key_material, self::WRAP_AAD, $nonce, $site_key );

		return wp_json_encode(
			array(
				'v'     => 1,
				'nonce' => base64_encode( $nonce ),
				'ct'    => base64_encode( $ciphertext ),
			)
		);
	}

	/**
	 * Unwraps key material previously wrapped under the current site key.
	 *
	 * @since 7.2.0
	 *
	 * @param string $wrapped Opaque wrapped form, as returned by wrap().
	 * @return string|WP_Error 32 raw bytes, or WP_Error if the site key is
	 *                         unavailable or the wrapped form does not
	 *                         decrypt.
	 */
	public function unwrap( $wrapped ) {
		$site_key = $this->get_site_key();

		if ( is_wp_error( $site_key ) ) {
			return $site_key;
		}

		$record = json_decode( $wrapped, true );

		if ( ! is_array( $record ) || ! isset( $record['v'], $record['nonce'], $record['ct'] ) || 1 !== $record['v'] ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The wrapped key material is malformed.' ) );
		}

		$nonce      = base64_decode( (string) $record['nonce'], true );
		$ciphertext = base64_decode( (string) $record['ct'], true );

		if ( false === $nonce || false === $ciphertext ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The wrapped key material is malformed.' ) );
		}

		$key_material = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $ciphertext, self::WRAP_AAD, $nonce, $site_key );

		if ( false === $key_material ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The wrapped key material could not be decrypted.' ) );
		}

		return $key_material;
	}

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
	 * Resolves the previous site key, for planned key rotation.
	 *
	 * `WP_SECRETS_KEY_PREVIOUS` supports rotating `WP_SECRETS_KEY`: on a
	 * site that has been running on the salts fallback, simply defining
	 * `WP_SECRETS_KEY` for the first time is itself a rotation, from the
	 * fallback to the constant. Since there is nothing else the previous
	 * key could be in that case, it is resolved automatically rather
	 * than requiring the operator to also set
	 * `WP_SECRETS_KEY_PREVIOUS` to a value equivalent to the fallback.
	 *
	 * @since 7.2.0
	 *
	 * @return string|WP_Error 32 raw bytes, or WP_Error if no previous key
	 *                         is available.
	 */
	public function get_previous_site_key() {
		if ( defined( 'WP_SECRETS_KEY_PREVIOUS' ) ) {
			return $this->decode_constant( WP_SECRETS_KEY_PREVIOUS );
		}

		if ( defined( 'WP_SECRETS_KEY' ) ) {
			return $this->derive_from_salts();
		}

		return new WP_Error( 'secret_key_provider_unavailable', __( 'No previous Secrets API site key is configured.' ) );
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
