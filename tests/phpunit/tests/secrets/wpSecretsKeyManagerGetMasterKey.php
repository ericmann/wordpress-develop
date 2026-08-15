<?php
/**
 * Tests for WP_Secrets_Key_Manager::get_master_key().
 *
 * @group secrets
 * @covers WP_Secrets_Key_Manager::get_master_key
 */
class Tests_Secrets_WpSecretsKeyManagerGetMasterKey extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 */
	public function test_returns_32_bytes() {
		$manager = new WP_Secrets_Key_Manager();

		$key = $manager->get_master_key();

		$this->assertIsString( $key );
		$this->assertSame( 32, strlen( $key ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_round_trips_through_storage_and_retrieval() {
		$manager = new WP_Secrets_Key_Manager();

		$first_call = $manager->get_master_key();

		// A fresh instance must read the same persisted, wrapped record.
		$second_call = ( new WP_Secrets_Key_Manager() )->get_master_key();

		$this->assertSame( $first_call, $second_call );
	}

	/**
	 * @ticket 64789
	 */
	public function test_master_key_is_generated_only_once() {
		$manager = new WP_Secrets_Key_Manager();

		$manager->get_master_key();
		$stored_after_first_call = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$manager->get_master_key();
		$stored_after_second_call = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$this->assertSame( $stored_after_first_call, $stored_after_second_call );
	}

	/**
	 * @ticket 64789
	 */
	public function test_stored_record_has_the_documented_shape() {
		$manager = new WP_Secrets_Key_Manager();
		$manager->get_master_key();

		$record = json_decode( get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION ), true );

		$this->assertIsArray( $record );
		$this->assertSame( 1, $record['v'] );
		$this->assertArrayHasKey( 'nonce', $record );
		$this->assertArrayHasKey( 'ct', $record );
		$this->assertNotFalse( base64_decode( $record['nonce'], true ) );
		$this->assertNotFalse( base64_decode( $record['ct'], true ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_tampered_ciphertext_fails_to_decrypt() {
		$manager = new WP_Secrets_Key_Manager();
		$manager->get_master_key();

		$this->corrupt_stored_field( 'ct' );

		$actual = $manager->get_master_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_decryption_failed', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_tampered_nonce_fails_to_decrypt() {
		$manager = new WP_Secrets_Key_Manager();
		$manager->get_master_key();

		$this->corrupt_stored_field( 'nonce' );

		$actual = $manager->get_master_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_decryption_failed', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_unknown_record_version_is_rejected() {
		$manager = new WP_Secrets_Key_Manager();
		$manager->get_master_key();

		$record      = json_decode( get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION ), true );
		$record['v'] = 2;
		update_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION, wp_json_encode( $record ), false );

		$actual = $manager->get_master_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_decryption_failed', $actual->get_error_code() );
	}

	/**
	 * Flips one byte of a base64-encoded field in the stored master key record.
	 *
	 * @param string $field Either 'ct' or 'nonce'.
	 */
	private function corrupt_stored_field( $field ) {
		$record = json_decode( get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION ), true );
		$raw    = base64_decode( $record[ $field ], true );

		$raw[0]           = chr( ord( $raw[0] ) ^ 0xFF );
		$record[ $field ] = base64_encode( $raw );

		update_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION, wp_json_encode( $record ), false );
	}
}
