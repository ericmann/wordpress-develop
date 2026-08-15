<?php
/**
 * Secrets API: WP_Secrets_Key_Manager class.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Manages the lifecycle of a Secrets API master key.
 *
 * Individual secrets are encrypted under a random 32-byte master key,
 * not directly under the site key. The site key only wraps the master
 * key, so rotating `WP_SECRETS_KEY` re-wraps one value rather than
 * rewriting every stored secret. AWS KMS documents the same envelope
 * pattern for client-side encryption, for the same reason.
 *
 * The same lifecycle - generate once, wrap under the site key, retry
 * with the previous key on rotation - applies to two different keys:
 * the per-site master key (`$network = false`), stored as a site
 * option, and the network root key (`$network = true`), stored as
 * network meta. A network of 500 sites derives each site's master key
 * from the one network root key rather than storing 500 independently
 * wrapped keys, so rotating `WP_SECRETS_KEY` re-wraps one value
 * network-wide, not one per site.
 *
 * This is an internal class with no public function wrapper: it is used
 * by the Secrets API cipher layer, not called directly by plugins.
 *
 * @since 7.2.0
 * @access private
 */
class WP_Secrets_Key_Manager {

	/**
	 * Option name for the wrapped per-site master key.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const MASTER_KEY_OPTION = '_wp_secrets_master_key';

	/**
	 * Network meta key for the wrapped network root key.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const NETWORK_ROOT_KEY_OPTION = '_wp_secrets_network_root_key';

	/**
	 * AAD binding the wrapped per-site master key to its purpose.
	 *
	 * Encrypting the master key under the same AAD used for anything
	 * else would let a wrapped master key record be swapped in wherever
	 * that other thing is read, and vice versa.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const MASTER_KEY_AAD = 'wp-secrets-master-key-v1';

	/**
	 * AAD binding the wrapped network root key to its purpose.
	 *
	 * Distinct from MASTER_KEY_AAD so a wrapped network root key cannot
	 * be swapped into a site's wrapped master key option, or vice versa,
	 * even where both happen to be wrapped under the same site key (the
	 * salts fallback derives the same key network-wide).
	 *
	 * @since 7.2.0
	 * @var string
	 */
	const NETWORK_ROOT_KEY_AAD = 'wp-secrets-network-root-key-v1';

	/**
	 * Provides the site key that wraps the master key.
	 *
	 * @since 7.2.0
	 * @var WP_Secrets_Config_Key_Provider
	 */
	private $key_provider;

	/**
	 * Whether this instance manages the network root key rather than a
	 * per-site master key.
	 *
	 * @since 7.2.0
	 * @var bool
	 */
	private $network;

	/**
	 * Constructor.
	 *
	 * @since 7.2.0
	 *
	 * @param WP_Secrets_Config_Key_Provider|null $key_provider Optional. Defaults to a new instance.
	 * @param bool                                $network      Optional. Whether to manage the network
	 *                                                           root key rather than the per-site master
	 *                                                           key. Default false.
	 */
	public function __construct( WP_Secrets_Config_Key_Provider $key_provider = null, $network = false ) {
		$this->key_provider = $key_provider ? $key_provider : new WP_Secrets_Config_Key_Provider();
		$this->network      = (bool) $network;
	}

	/**
	 * Returns the site's master key, generating and persisting one if needed.
	 *
	 * If the current site key fails to unwrap a stored master key, this
	 * retries with the previous site key. On success, the master key is
	 * transparently re-wrapped under the current key and persisted (one
	 * option write) so the retry is not needed again. If both keys fail,
	 * nothing is written: the stored record is left exactly as it was,
	 * so no data is destroyed by a rotation that has not finished yet.
	 *
	 * @since 7.2.0
	 *
	 * @return string|WP_Error 32 raw bytes, or WP_Error if the site key is
	 *                         unavailable or the stored master key does
	 *                         not decrypt under either the current or the
	 *                         previous site key.
	 */
	public function get_master_key() {
		$site_key = $this->key_provider->get_site_key();

		if ( is_wp_error( $site_key ) ) {
			return $site_key;
		}

		$stored = $this->network ? get_site_option( self::NETWORK_ROOT_KEY_OPTION ) : get_option( self::MASTER_KEY_OPTION );

		if ( false === $stored ) {
			return $this->generate_master_key( $site_key );
		}

		$unwrapped = $this->unwrap_master_key( $stored, $site_key );

		if ( ! is_wp_error( $unwrapped ) ) {
			return $unwrapped;
		}

		return $this->retry_with_previous_site_key( $stored, $site_key, $unwrapped );
	}

	/**
	 * Retries unwrapping the master key with the previous site key.
	 *
	 * @since 7.2.0
	 *
	 * @param string   $stored           The raw option value.
	 * @param string   $current_site_key 32 raw bytes.
	 * @param WP_Error $original_error   The error from the current key attempt,
	 *                                   returned unchanged if the previous key
	 *                                   is also unavailable or does not work.
	 * @return string|WP_Error 32 raw bytes, or WP_Error if unavailable.
	 */
	private function retry_with_previous_site_key( $stored, $current_site_key, WP_Error $original_error ) {
		$previous_site_key = $this->key_provider->get_previous_site_key();

		if ( is_wp_error( $previous_site_key ) ) {
			return $original_error;
		}

		$unwrapped = $this->unwrap_master_key( $stored, $previous_site_key );

		if ( is_wp_error( $unwrapped ) ) {
			return $unwrapped;
		}

		$this->store_master_key( $unwrapped, $current_site_key );

		return $unwrapped;
	}

	/**
	 * Generates, wraps, and persists a new master key.
	 *
	 * @since 7.2.0
	 *
	 * @param string $site_key 32 raw bytes.
	 * @return string 32 raw bytes: the new master key.
	 */
	private function generate_master_key( $site_key ) {
		$master_key = random_bytes( 32 );

		$this->store_master_key( $master_key, $site_key );

		return $master_key;
	}

	/**
	 * Wraps a master key under the site key and persists it.
	 *
	 * @since 7.2.0
	 *
	 * @param string $master_key 32 raw bytes.
	 * @param string $site_key   32 raw bytes.
	 */
	private function store_master_key( $master_key, $site_key ) {
		$nonce      = random_bytes( SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES );
		$ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt( $master_key, $this->get_aad(), $nonce, $site_key );

		$record = array(
			'v'     => 1,
			'nonce' => base64_encode( $nonce ),
			'ct'    => base64_encode( $ciphertext ),
		);

		if ( $this->network ) {
			update_site_option( self::NETWORK_ROOT_KEY_OPTION, wp_json_encode( $record ) );
		} else {
			update_option( self::MASTER_KEY_OPTION, wp_json_encode( $record ), false );
		}
	}

	/**
	 * Returns the AAD for whichever key this instance manages.
	 *
	 * @since 7.2.0
	 *
	 * @return string
	 */
	private function get_aad() {
		return $this->network ? self::NETWORK_ROOT_KEY_AAD : self::MASTER_KEY_AAD;
	}

	/**
	 * Unwraps a stored, wrapped master key.
	 *
	 * @since 7.2.0
	 *
	 * @param string $stored   The raw option value.
	 * @param string $site_key 32 raw bytes.
	 * @return string|WP_Error 32 raw bytes, or WP_Error if the record is
	 *                         malformed or does not decrypt.
	 */
	private function unwrap_master_key( $stored, $site_key ) {
		$record = json_decode( $stored, true );

		if ( ! is_array( $record ) || ! isset( $record['v'], $record['nonce'], $record['ct'] ) || 1 !== $record['v'] ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The stored Secrets API master key record is malformed.' ) );
		}

		$nonce      = base64_decode( (string) $record['nonce'], true );
		$ciphertext = base64_decode( (string) $record['ct'], true );

		if ( false === $nonce || false === $ciphertext ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The stored Secrets API master key record is malformed.' ) );
		}

		$master_key = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt( $ciphertext, $this->get_aad(), $nonce, $site_key );

		if ( false === $master_key ) {
			return new WP_Error( 'secret_decryption_failed', __( 'The stored Secrets API master key could not be decrypted.' ) );
		}

		return $master_key;
	}
}
