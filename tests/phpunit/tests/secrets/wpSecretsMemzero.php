<?php
/**
 * Tests for wp_secrets_memzero().
 *
 * @group secrets
 * @covers ::wp_secrets_memzero
 */
class Tests_Secrets_WpSecretsMemzero extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 */
	public function test_zeroes_via_sodium_extension_when_available() {
		if ( ! extension_loaded( 'sodium' ) ) {
			$this->markTestSkipped( 'The sodium extension is not loaded in this environment.' );
		}

		$secret = 'correct-horse-battery-staple';

		wp_secrets_memzero( $secret );

		$this->assertNotSame( 'correct-horse-battery-staple', $secret );
		$this->assertEmpty( $secret );
	}

	/**
	 * @ticket 64789
	 */
	public function test_falls_back_to_null_byte_overwrite_without_sodium_extension() {
		if ( extension_loaded( 'sodium' ) ) {
			$this->markTestSkipped( 'The sodium extension is loaded in this environment; the polyfill fallback path cannot be exercised.' );
		}

		$secret = 'correct-horse-battery-staple';
		$length = strlen( $secret );

		wp_secrets_memzero( $secret );

		$this->assertSame( str_repeat( "\0", $length ), $secret );
	}
}
