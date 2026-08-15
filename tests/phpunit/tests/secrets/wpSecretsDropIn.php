<?php
/**
 * Tests for the secrets.php drop-in's two pluggable axes.
 *
 * @group secrets
 * @covers ::wp_secrets_get_store
 * @covers ::wp_using_secrets_dropin
 * @covers WP_Secrets_Key_Manager::get_master_key
 */
class Tests_Secrets_WpSecretsDropIn extends WP_UnitTestCase {

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	public function set_up() {
		parent::set_up();

		unset( $GLOBALS['wp_secrets_store'], $GLOBALS['wp_secrets_key_provider'] );
	}

	public function tear_down() {
		unset( $GLOBALS['wp_secrets_store'], $GLOBALS['wp_secrets_key_provider'] );

		parent::tear_down();
	}

	/**
	 * @ticket 64789
	 */
	public function test_neither_axis_is_overridden_by_default() {
		$this->assertSame(
			array(
				'store'        => false,
				'key_provider' => false,
			),
			wp_using_secrets_dropin()
		);
	}

	/**
	 * @ticket 64789
	 */
	public function test_drop_in_overrides_the_store() {
		$fake_store                  = new Tests_Secrets_Fake_Store();
		$GLOBALS['wp_secrets_store'] = $fake_store;

		wp_set_secret( self::NAME, self::PLAINTEXT );

		$this->assertTrue( wp_using_secrets_dropin()['store'] );
		$this->assertFalse( wp_using_secrets_dropin()['key_provider'] );
		$this->assertNotEmpty( $fake_store->data, 'The fake store should have received the write.' );
		$this->assertFalse( get_option( WP_Secrets_Option_Store::SITE_PREFIX . self::NAME ), 'The default option store must not also receive the write.' );

		$this->assertSame( self::PLAINTEXT, wp_get_secret( self::NAME )->reveal() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_drop_in_overrides_the_key_provider() {
		$fake_provider                      = new Tests_Secrets_Fake_Wrapping_Key_Provider();
		$GLOBALS['wp_secrets_key_provider'] = $fake_provider;

		wp_set_secret( self::NAME, self::PLAINTEXT );

		$this->assertFalse( wp_using_secrets_dropin()['store'] );
		$this->assertTrue( wp_using_secrets_dropin()['key_provider'] );
		$this->assertNotEmpty( $fake_provider->wrap_calls, 'The fake key provider should have been asked to wrap the master key.' );

		$this->assertSame( self::PLAINTEXT, wp_get_secret( self::NAME )->reveal() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_drop_in_overrides_both_axes() {
		$fake_store    = new Tests_Secrets_Fake_Store();
		$fake_provider = new Tests_Secrets_Fake_Wrapping_Key_Provider();

		$GLOBALS['wp_secrets_store']        = $fake_store;
		$GLOBALS['wp_secrets_key_provider'] = $fake_provider;

		wp_set_secret( self::NAME, self::PLAINTEXT );

		$this->assertSame(
			array(
				'store'        => true,
				'key_provider' => true,
			),
			wp_using_secrets_dropin()
		);
		$this->assertNotEmpty( $fake_store->data );
		$this->assertNotEmpty( $fake_provider->wrap_calls );
		$this->assertSame( self::PLAINTEXT, wp_get_secret( self::NAME )->reveal() );
	}

	/**
	 * The tempting bug here is a try/catch that quietly falls back to the
	 * default option store. There must be no such fallback.
	 *
	 * @ticket 64789
	 */
	public function test_failing_drop_in_store_fails_closed_with_no_fallback() {
		$GLOBALS['wp_secrets_store'] = new Tests_Secrets_Failing_Store();

		$actual = wp_set_secret( self::NAME, self::PLAINTEXT );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_store_unavailable', $actual->get_error_code() );
		$this->assertFalse( get_option( WP_Secrets_Option_Store::SITE_PREFIX . self::NAME ), 'A failing drop-in store must not fall back to the default option store.' );
	}

	/**
	 * @ticket 64789
	 */
	public function test_failing_drop_in_key_provider_fails_closed_with_no_fallback() {
		$GLOBALS['wp_secrets_key_provider'] = new Tests_Secrets_Failing_Key_Provider();

		$actual = wp_set_secret( self::NAME, self::PLAINTEXT );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_key_provider_unavailable', $actual->get_error_code() );
		$this->assertFalse( get_option( WP_Secrets_Option_Store::SITE_PREFIX . self::NAME ), 'A failing drop-in key provider must not fall back to the config-based default.' );
	}
}

/**
 * A minimal in-memory WP_Secrets_Store test double.
 */
class Tests_Secrets_Fake_Store implements WP_Secrets_Store {

	public $data = array();

	public function get( $name, $network = false ) {
		$key = $this->key( $name, $network );

		return isset( $this->data[ $key ] ) ? $this->data[ $key ] : null;
	}

	public function set( $name, $record, $network = false ) {
		$this->data[ $this->key( $name, $network ) ] = $record;

		return true;
	}

	public function delete( $name, $network = false ) {
		unset( $this->data[ $this->key( $name, $network ) ] );

		return true;
	}

	public function list_names( $network = false ) {
		$prefix = $network ? 'network:' : 'site:';
		$names  = array();

		foreach ( array_keys( $this->data ) as $key ) {
			if ( str_starts_with( $key, $prefix ) ) {
				$names[] = substr( $key, strlen( $prefix ) );
			}
		}

		return $names;
	}

	private function key( $name, $network ) {
		return ( $network ? 'network:' : 'site:' ) . $name;
	}
}

/**
 * A WP_Secrets_Store test double that always fails.
 */
class Tests_Secrets_Failing_Store implements WP_Secrets_Store {

	public function get( $name, $network = false ) {
		return new WP_Error( 'secret_store_unavailable', 'Test double: store unavailable.' );
	}

	public function set( $name, $record, $network = false ) {
		return new WP_Error( 'secret_store_unavailable', 'Test double: store unavailable.' );
	}

	public function delete( $name, $network = false ) {
		return new WP_Error( 'secret_store_unavailable', 'Test double: store unavailable.' );
	}

	public function list_names( $network = false ) {
		return new WP_Error( 'secret_store_unavailable', 'Test double: store unavailable.' );
	}
}

/**
 * A minimal WP_Secrets_Key_Provider test double that records wrap() calls.
 */
class Tests_Secrets_Fake_Wrapping_Key_Provider implements WP_Secrets_Key_Provider {

	const PREFIX = 'FAKE-WRAPPED:';

	public $wrap_calls = array();

	public function wrap( $key_material ) {
		$this->wrap_calls[] = $key_material;

		return self::PREFIX . base64_encode( $key_material );
	}

	public function unwrap( $wrapped ) {
		if ( 0 !== strpos( $wrapped, self::PREFIX ) ) {
			return new WP_Error( 'secret_decryption_failed', 'Test double: not wrapped by this provider.' );
		}

		return base64_decode( substr( $wrapped, strlen( self::PREFIX ) ) );
	}
}

/**
 * A WP_Secrets_Key_Provider test double that always fails.
 */
class Tests_Secrets_Failing_Key_Provider implements WP_Secrets_Key_Provider {

	public function wrap( $key_material ) {
		return new WP_Error( 'secret_key_provider_unavailable', 'Test double: key provider unavailable.' );
	}

	public function unwrap( $wrapped ) {
		return new WP_Error( 'secret_key_provider_unavailable', 'Test double: key provider unavailable.' );
	}
}
