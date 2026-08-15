<?php
/**
 * Tests for WP_Secrets_Cipher::fingerprint().
 *
 * @group secrets
 * @covers WP_Secrets_Cipher::fingerprint
 */
class Tests_Secrets_WpSecretsCipherFingerprint extends WP_UnitTestCase {

	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	/**
	 * @var WP_Secrets_Cipher
	 */
	private $cipher;

	public function set_up() {
		parent::set_up();

		$this->cipher = new WP_Secrets_Cipher();
	}

	/**
	 * @ticket 64789
	 */
	public function test_is_32_hex_characters() {
		$fingerprint = $this->cipher->fingerprint( self::PLAINTEXT, random_bytes( 32 ) );

		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $fingerprint );
	}

	/**
	 * @ticket 64789
	 */
	public function test_is_stable_within_the_same_key() {
		$master_key = random_bytes( 32 );

		$first  = $this->cipher->fingerprint( self::PLAINTEXT, $master_key );
		$second = $this->cipher->fingerprint( self::PLAINTEXT, $master_key );

		$this->assertSame( $first, $second );
	}

	/**
	 * @ticket 64789
	 */
	public function test_differs_across_master_keys() {
		$fingerprint_a = $this->cipher->fingerprint( self::PLAINTEXT, random_bytes( 32 ) );
		$fingerprint_b = $this->cipher->fingerprint( self::PLAINTEXT, random_bytes( 32 ) );

		$this->assertNotSame( $fingerprint_a, $fingerprint_b );
	}

	/**
	 * @ticket 64789
	 */
	public function test_differs_for_different_plaintext_under_the_same_key() {
		$master_key = random_bytes( 32 );

		$fingerprint_a = $this->cipher->fingerprint( 'sk-live-abc123-do-not-leak-me', $master_key );
		$fingerprint_b = $this->cipher->fingerprint( 'sk-live-xyz789-do-not-leak-me', $master_key );

		$this->assertNotSame( $fingerprint_a, $fingerprint_b );
	}
}
