<?php
/**
 * Secrets API: WP_Secrets_Cipher class.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Encrypts and decrypts individual secret values under the master key.
 *
 * Every secret value is bound to its identity: the AAD includes the
 * secret's name, which version slot it occupies, and the site it
 * belongs to. A row copied verbatim between names, slots, or sites -
 * whether by a bug or by an attacker who can write to the options
 * table but not read the master key - fails to decrypt rather than
 * silently succeeding somewhere it does not belong.
 *
 * This is an internal class with no public function wrapper.
 *
 * @since 7.2.0
 * @access private
 */
class WP_Secrets_Cipher {

	/**
	 * Encrypts a secret value, binding the ciphertext to its identity.
	 *
	 * @since 7.2.0
	 *
	 * @param string $plaintext  Secret plaintext.
	 * @param string $master_key 32 raw bytes.
	 * @param string $name       Namespaced secret name.
	 * @param string $slot       'current' or 'previous'.
	 * @param int    $site_id    Site ID the secret belongs to.
	 * @return array {
	 *     The encrypted value.
	 *
	 *     @type string $ct    Base64-encoded ciphertext.
	 *     @type string $nonce Base64-encoded nonce.
	 * }
	 */
	public function encrypt( $plaintext, $master_key, $name, $slot, $site_id ) {
		$nonce      = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		$ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( $plaintext, $this->build_aad( $name, $slot, $site_id ), $nonce, $master_key );

		return array(
			'ct'    => base64_encode( $ciphertext ),
			'nonce' => base64_encode( $nonce ),
		);
	}

	/**
	 * Decrypts a secret value, verifying it is bound to the given identity.
	 *
	 * @since 7.2.0
	 *
	 * @param string $ct         Base64-encoded ciphertext.
	 * @param string $nonce      Base64-encoded nonce.
	 * @param string $master_key 32 raw bytes.
	 * @param string $name       Namespaced secret name.
	 * @param string $slot       'current' or 'previous'.
	 * @param int    $site_id    Site ID the secret belongs to.
	 * @return string|WP_Error Plaintext, or WP_Error if it does not decrypt.
	 */
	public function decrypt( $ct, $nonce, $master_key, $name, $slot, $site_id ) {
		$raw_ciphertext = base64_decode( (string) $ct, true );
		$raw_nonce      = base64_decode( (string) $nonce, true );

		if ( false === $raw_ciphertext || false === $raw_nonce ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The stored secret record is malformed.' ) );
		}

		$plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $raw_ciphertext, $this->build_aad( $name, $slot, $site_id ), $raw_nonce, $master_key );

		if ( false === $plaintext ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The secret could not be decrypted.' ) );
		}

		return $plaintext;
	}

	/**
	 * Builds the name-bound AAD for a secret value.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name    Namespaced secret name.
	 * @param string $slot    'current' or 'previous'.
	 * @param int    $site_id Site ID the secret belongs to.
	 * @return string The AAD.
	 */
	private function build_aad( $name, $slot, $site_id ) {
		return implode( "\0", array( 'wp-secret-v1', $name, $slot, (string) $site_id ) );
	}

	/**
	 * Computes the keyed fingerprint of a secret value.
	 *
	 * The fingerprint is keyed, not a bare hash. An unkeyed fingerprint of
	 * a low-entropy secret would be a brute-force oracle for anyone
	 * holding the database - precisely the attacker this API's threat
	 * model is defending against. Fingerprints do not survive a master
	 * key change; they exist to confirm a re-entered value matches
	 * within one site's key lifetime, not across it.
	 *
	 * @since 7.2.0
	 *
	 * @param string $plaintext  Secret plaintext.
	 * @param string $master_key 32 raw bytes.
	 * @return string 32 lowercase hex characters.
	 */
	public function fingerprint( $plaintext, $master_key ) {
		$fingerprint_key = sodium_crypto_kdf_derive_from_key( 32, 0, 'wpsecfpr', $master_key );

		return bin2hex( sodium_crypto_generichash( $plaintext, $fingerprint_key, 16 ) );
	}
}
