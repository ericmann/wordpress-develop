<?php
/**
 * Tests for WP_Secrets_Config_Key_Provider::get_site_key().
 *
 * @group secrets
 * @covers WP_Secrets_Config_Key_Provider::get_site_key
 */
class Tests_Secrets_WpSecretsConfigKeyProviderGetSiteKey extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_returns_32_bytes_for_a_valid_constant() {
		$raw = str_repeat( 'a', 32 );
		define( 'WP_SECRETS_KEY', base64_encode( $raw ) );

		$provider = new WP_Secrets_Config_Key_Provider();
		$key      = $provider->get_site_key();

		$this->assertSame( $raw, $key );
		$this->assertSame( 32, strlen( $key ) );
	}

	/**
	 * @ticket 64789
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_rejects_a_constant_of_the_wrong_length() {
		define( 'WP_SECRETS_KEY', base64_encode( str_repeat( 'a', 16 ) ) );

		$provider = new WP_Secrets_Config_Key_Provider();
		$actual   = $provider->get_site_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_key_provider_unavailable', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_rejects_a_constant_that_is_not_base64() {
		define( 'WP_SECRETS_KEY', 'not-valid-base64!!! ***' );

		$provider = new WP_Secrets_Config_Key_Provider();
		$actual   = $provider->get_site_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_key_provider_unavailable', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_returns_error_when_constant_is_not_defined() {
		$this->assertFalse( defined( 'WP_SECRETS_KEY' ), 'This test assumes WP_SECRETS_KEY is not defined in the base test environment.' );

		$provider = new WP_Secrets_Config_Key_Provider();
		$actual   = $provider->get_site_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_key_provider_unavailable', $actual->get_error_code() );
	}
}
