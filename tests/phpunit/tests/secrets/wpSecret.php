<?php
/**
 * Tests for WP_Secret.
 *
 * @group secrets
 * @covers WP_Secret
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpSecret extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const PLAINTEXT   = 'sk-live-abc123-do-not-leak-me';
	const NAME        = 'plugin-slug/secret-name';
	const FINGERPRINT = '0123456789abcdef0123456789abcdef';

	/**
	 * @ticket 64789
	 */
	public function test_reveal_returns_the_plaintext_value() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->assertSame( self::PLAINTEXT, $secret->reveal() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_get_name_returns_the_name() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->assertSame( self::NAME, $secret->get_name() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_get_fingerprint_returns_the_fingerprint() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->assertSame( self::FINGERPRINT, $secret->get_fingerprint() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_to_string_redacts_the_value() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$as_string         = (string) $secret;
		$via_interpolation = "prefix {$secret} suffix";

		$this->assertSame( '[redacted secret: ' . self::NAME . ']', $as_string );
		$this->assertDoesNotContainSecret( self::PLAINTEXT, $as_string );
		$this->assertDoesNotContainSecret( self::PLAINTEXT, $via_interpolation );
	}

	/**
	 * @ticket 64789
	 */
	public function test_debug_info_redacts_the_value() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$debug_info = $secret->__debugInfo();

		$this->assertSame(
			array(
				'name'        => self::NAME,
				'value'       => '[redacted]',
				'fingerprint' => self::FINGERPRINT,
			),
			$debug_info
		);

		ob_start();
		var_dump( $secret );
		$dump = ob_get_clean();

		$this->assertDoesNotContainSecret( self::PLAINTEXT, $dump );
		$this->assertStringContainsString( '[redacted]', $dump );
	}

	/**
	 * @ticket 64789
	 */
	public function test_json_serialize_redacts_the_value() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$encoded = wp_json_encode( $secret );
		$decoded = json_decode( $encoded, true );

		$this->assertSame( self::NAME, $decoded['name'] );
		$this->assertSame( '[redacted]', $decoded['value'] );
		$this->assertDoesNotContainSecret( self::PLAINTEXT, $encoded );
	}

	/**
	 * @ticket 64789
	 */
	public function test_sleep_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->expectException( LogicException::class );
		$secret->__sleep();
	}

	/**
	 * @ticket 64789
	 */
	public function test_wakeup_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->expectException( LogicException::class );
		$secret->__wakeup();
	}

	/**
	 * @ticket 64789
	 */
	public function test_serialize_method_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->expectException( LogicException::class );
		$secret->__serialize();
	}

	/**
	 * @ticket 64789
	 */
	public function test_unserialize_method_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->expectException( LogicException::class );
		$secret->__unserialize( array() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_native_serialize_function_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->expectException( LogicException::class );
		serialize( $secret );
	}

	/**
	 * @ticket 64789
	 */
	public function test_clone_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, self::FINGERPRINT );

		$this->expectException( LogicException::class );
		clone $secret;
	}

	/**
	 * @ticket 64789
	 */
	public function test_class_is_final() {
		$reflection = new ReflectionClass( WP_Secret::class );

		$this->assertTrue( $reflection->isFinal() );
	}
}
