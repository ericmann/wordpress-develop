<?php
/**
 * Tests for WP_Secrets_Cipher.
 *
 * @group secrets
 * @covers WP_Secrets_Cipher
 */
class Tests_Secrets_WpSecretsCipher extends WP_UnitTestCase {

	const PLAINTEXT  = 'sk-live-abc123-do-not-leak-me';
	const NAME       = 'plugin-slug/secret-name';
	const OTHER_NAME = 'plugin-slug/other-secret';
	const SLOT       = 'current';
	const OTHER_SLOT = 'previous';
	const SITE_ID    = 1;
	const OTHER_SITE = 2;

	/**
	 * @var WP_Secrets_Cipher
	 */
	private $cipher;

	/**
	 * @var string 32 raw bytes.
	 */
	private $master_key;

	public function set_up() {
		parent::set_up();

		$this->cipher     = new WP_Secrets_Cipher();
		$this->master_key = random_bytes( 32 );
	}

	/**
	 * @ticket 64789
	 */
	public function test_round_trip() {
		$encrypted = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$decrypted = $this->cipher->decrypt( $encrypted['ct'], $encrypted['nonce'], $this->master_key, self::NAME, self::SLOT, self::SITE_ID );

		$this->assertSame( self::PLAINTEXT, $decrypted );
	}

	/**
	 * @ticket 64789
	 */
	public function test_wrong_name_fails() {
		$encrypted = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$decrypted = $this->cipher->decrypt( $encrypted['ct'], $encrypted['nonce'], $this->master_key, self::OTHER_NAME, self::SLOT, self::SITE_ID );

		$this->assertWPError( $decrypted );
		$this->assertSame( 'secret_decryption_failed', $decrypted->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_wrong_slot_fails() {
		// This is the "copy current into previous verbatim" scenario from the design doc.
		$encrypted = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$decrypted = $this->cipher->decrypt( $encrypted['ct'], $encrypted['nonce'], $this->master_key, self::NAME, self::OTHER_SLOT, self::SITE_ID );

		$this->assertWPError( $decrypted );
		$this->assertSame( 'secret_decryption_failed', $decrypted->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_wrong_site_fails() {
		$encrypted = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$decrypted = $this->cipher->decrypt( $encrypted['ct'], $encrypted['nonce'], $this->master_key, self::NAME, self::SLOT, self::OTHER_SITE );

		$this->assertWPError( $decrypted );
		$this->assertSame( 'secret_decryption_failed', $decrypted->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_tampered_ciphertext_fails() {
		$encrypted = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$tampered  = $this->flip_one_byte( $encrypted['ct'] );

		$decrypted = $this->cipher->decrypt( $tampered, $encrypted['nonce'], $this->master_key, self::NAME, self::SLOT, self::SITE_ID );

		$this->assertWPError( $decrypted );
		$this->assertSame( 'secret_decryption_failed', $decrypted->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_tampered_nonce_fails() {
		$encrypted = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$tampered  = $this->flip_one_byte( $encrypted['nonce'] );

		$decrypted = $this->cipher->decrypt( $encrypted['ct'], $tampered, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );

		$this->assertWPError( $decrypted );
		$this->assertSame( 'secret_decryption_failed', $decrypted->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_wrong_master_key_fails() {
		$encrypted     = $this->cipher->encrypt( self::PLAINTEXT, $this->master_key, self::NAME, self::SLOT, self::SITE_ID );
		$different_key = random_bytes( 32 );
		$decrypted     = $this->cipher->decrypt( $encrypted['ct'], $encrypted['nonce'], $different_key, self::NAME, self::SLOT, self::SITE_ID );

		$this->assertWPError( $decrypted );
		$this->assertSame( 'secret_decryption_failed', $decrypted->get_error_code() );
	}

	/**
	 * Flips one byte of a base64-encoded value, without changing its length.
	 *
	 * @param string $encoded Base64-encoded value.
	 * @return string Base64-encoded value with one raw byte flipped.
	 */
	private function flip_one_byte( $encoded ) {
		$raw    = base64_decode( $encoded, true );
		$raw[0] = chr( ord( $raw[0] ) ^ 0xFF );

		return base64_encode( $raw );
	}
}
