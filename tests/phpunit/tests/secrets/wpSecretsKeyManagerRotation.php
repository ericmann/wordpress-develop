<?php
/**
 * Tests for WP_Secrets_Key_Manager's key rotation support.
 *
 * @group secrets
 * @covers WP_Secrets_Key_Manager::get_master_key
 * @covers WP_Secrets_Config_Key_Provider::get_previous_site_key
 */
class Tests_Secrets_WpSecretsKeyManagerRotation extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 */
	public function test_current_key_works_no_write() {
		$provider = new Tests_Secrets_Fake_Key_Provider( random_bytes( 32 ) );

		$original_master_key = ( new WP_Secrets_Key_Manager( $provider ) )->get_master_key();
		$stored_before       = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$second_master_key = ( new WP_Secrets_Key_Manager( $provider ) )->get_master_key();
		$stored_after      = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$this->assertSame( $original_master_key, $second_master_key );
		$this->assertSame( $stored_before, $stored_after, 'A working current key must not cause any write.' );
	}

	/**
	 * @ticket 64789
	 */
	public function test_current_fails_previous_works_rewraps_and_writes_once() {
		$key_a = random_bytes( 32 );
		$key_b = random_bytes( 32 );

		// Seed a master key wrapped under key A, as if A used to be current.
		$original_master_key = ( new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_a ) ) )->get_master_key();
		$stored_under_a      = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		// B is now current; A is the previous key.
		$unwrapped      = ( new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_b, $key_a ) ) )->get_master_key();
		$stored_under_b = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$this->assertSame( $original_master_key, $unwrapped );
		$this->assertNotSame( $stored_under_a, $stored_under_b, 'The master key should have been re-wrapped and persisted under the current key.' );

		// A subsequent read no longer needs the previous key at all.
		$manager_without_previous = new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_b ) );
		$this->assertSame( $original_master_key, $manager_without_previous->get_master_key() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_both_keys_fail_no_data_destroyed() {
		$key_a = random_bytes( 32 );
		$key_b = random_bytes( 32 );
		$key_c = random_bytes( 32 );

		( new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_a ) ) )->get_master_key();
		$stored_before = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$actual = ( new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_b, $key_c ) ) )->get_master_key();

		$stored_after = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_decryption_failed', $actual->get_error_code() );
		$this->assertSame( $stored_before, $stored_after, 'No data should be destroyed when both keys fail.' );
	}

	/**
	 * @ticket 64789
	 */
	public function test_no_previous_key_configured_fails_like_both_failing() {
		$key_a = random_bytes( 32 );
		$key_b = random_bytes( 32 );

		( new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_a ) ) )->get_master_key();

		$actual = ( new WP_Secrets_Key_Manager( new Tests_Secrets_Fake_Key_Provider( $key_b ) ) )->get_master_key();

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_decryption_failed', $actual->get_error_code() );
	}

	/**
	 * Defining WP_SECRETS_KEY on a site that has been running on the
	 * salts fallback is the "current fails, previous works" case with
	 * the fallback as previous - an automatic upgrade, not a re-entry
	 * event. WP_SECRETS_KEY_PREVIOUS is not required for this specific
	 * transition.
	 *
	 * @ticket 64789
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_salts_to_constant_upgrade_is_automatic() {
		$this->assertFalse( defined( 'WP_SECRETS_KEY' ), 'This test assumes WP_SECRETS_KEY is not defined yet.' );

		// Generate a master key while still on the salts fallback.
		$original_master_key = ( new WP_Secrets_Key_Manager() )->get_master_key();
		$stored_under_salts  = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		// The operator now defines WP_SECRETS_KEY, without WP_SECRETS_KEY_PREVIOUS.
		define( 'WP_SECRETS_KEY', base64_encode( random_bytes( 32 ) ) );

		$upgraded              = ( new WP_Secrets_Key_Manager() )->get_master_key();
		$stored_under_constant = get_option( WP_Secrets_Key_Manager::MASTER_KEY_OPTION );

		$this->assertSame( $original_master_key, $upgraded );
		$this->assertNotSame( $stored_under_salts, $stored_under_constant, 'The upgrade should re-wrap the master key under the new constant.' );

		// A second read should succeed on the constant alone.
		$this->assertSame( $original_master_key, ( new WP_Secrets_Key_Manager() )->get_master_key() );
	}
}

/**
 * A WP_Secrets_Config_Key_Provider test double returning fixed key values.
 *
 * Letting rotation scenarios inject arbitrary current/previous key pairs
 * directly, rather than relying on real constants, avoids needing
 * @runInSeparateProcess for every rotation test - only the test that
 * exercises the real constant-resolution behavior needs it.
 */
class Tests_Secrets_Fake_Key_Provider extends WP_Secrets_Config_Key_Provider {

	/**
	 * @var string
	 */
	private $site_key;

	/**
	 * @var string|null
	 */
	private $previous_site_key;

	/**
	 * @param string      $site_key          32 raw bytes.
	 * @param string|null $previous_site_key Optional. 32 raw bytes.
	 */
	public function __construct( $site_key, $previous_site_key = null ) {
		$this->site_key          = $site_key;
		$this->previous_site_key = $previous_site_key;
	}

	public function get_site_key() {
		return $this->site_key;
	}

	public function get_previous_site_key() {
		if ( null === $this->previous_site_key ) {
			return new WP_Error( 'secret_key_provider_unavailable', 'No previous key configured for this test double.' );
		}

		return $this->previous_site_key;
	}
}
