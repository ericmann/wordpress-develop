<?php
/**
 * Tests for wp_set_secret()'s two version slots.
 *
 * @group secrets
 * @covers ::wp_set_secret
 */
class Tests_Secrets_WpSetSecretVersionSlots extends WP_UnitTestCase {

	const NAME = 'plugin-slug/secret-name';

	/**
	 * @ticket 64789
	 */
	public function test_first_write_has_no_previous_slot() {
		wp_set_secret( self::NAME, 'value-a' );

		$record = $this->get_record();

		$this->assertNull( $record['previous'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_overwrite_demotes_current_to_previous() {
		wp_set_secret( self::NAME, 'value-a' );
		wp_set_secret( self::NAME, 'value-b' );

		$this->assertSame( 'value-b', wp_get_secret( self::NAME )->reveal() );
		$this->assertSame( 'value-a', $this->decrypt_previous_slot() );
	}

	/**
	 * The design doc calls this out explicitly: the previous slot must
	 * actually decrypt, not merely exist. Its ciphertext is re-encrypted
	 * under its own AAD rather than copied verbatim from current (see
	 * the WP_Secrets_Cipher tests for what happens when it is copied).
	 *
	 * @ticket 64789
	 */
	public function test_previous_slot_is_readable() {
		wp_set_secret( self::NAME, 'value-a' );
		wp_set_secret( self::NAME, 'value-b' );

		$decrypted = $this->decrypt_previous_slot();

		$this->assertNotWPError( $decrypted );
		$this->assertSame( 'value-a', $decrypted );
	}

	/**
	 * @ticket 64789
	 */
	public function test_third_write_discards_the_oldest_value() {
		wp_set_secret( self::NAME, 'value-a' );
		wp_set_secret( self::NAME, 'value-b' );
		wp_set_secret( self::NAME, 'value-c' );

		$this->assertSame( 'value-c', wp_get_secret( self::NAME )->reveal() );
		$this->assertSame( 'value-b', $this->decrypt_previous_slot() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_demoted_previous_preserves_the_original_fingerprint_and_created_timestamp() {
		wp_set_secret( self::NAME, 'value-a' );
		$original_current = $this->get_record()['current'];

		wp_set_secret( self::NAME, 'value-b' );
		$demoted_previous = $this->get_record()['previous'];

		$this->assertSame( $original_current['fp'], $demoted_previous['fp'] );
		$this->assertSame( $original_current['created'], $demoted_previous['created'] );
	}

	/**
	 * Fetches and JSON-decodes the raw stored record for the test secret.
	 *
	 * @return array
	 */
	private function get_record() {
		$option_name = WP_Secrets_Option_Store::SITE_PREFIX . self::NAME;

		return json_decode( get_option( $option_name ), true );
	}

	/**
	 * Decrypts the previous slot of the stored record for the test secret.
	 *
	 * @return string|WP_Error
	 */
	private function decrypt_previous_slot() {
		$record     = $this->get_record();
		$master_key = ( new WP_Secrets_Key_Manager() )->get_master_key();

		return ( new WP_Secrets_Cipher() )->decrypt(
			$record['previous']['ct'],
			$record['previous']['nonce'],
			$master_key,
			self::NAME,
			'previous',
			wp_secrets_current_site_id()
		);
	}
}
