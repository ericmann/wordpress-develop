<?php
/**
 * Tests for WP_Secrets_Option_Store.
 *
 * @group secrets
 * @covers WP_Secrets_Option_Store
 */
class Tests_Secrets_WpSecretsOptionStore extends WP_UnitTestCase {

	const NAME   = 'plugin-slug/secret-name';
	const RECORD = '{"v":1,"current":{"ct":"YWJj","nonce":"eHl6","fp":"aabbcc","created":1755100000},"previous":null,"needs_rotation":false,"updated":1755100000}';

	/**
	 * @var WP_Secrets_Option_Store
	 */
	private $store;

	public function set_up() {
		parent::set_up();

		$this->store = new WP_Secrets_Option_Store();
	}

	/**
	 * @ticket 64789
	 */
	public function test_get_returns_null_when_absent() {
		$this->assertNull( $this->store->get( self::NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_set_then_get_round_trips() {
		$this->store->set( self::NAME, self::RECORD );

		$this->assertSame( self::RECORD, $this->store->get( self::NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_set_overwrites_an_existing_record() {
		$this->store->set( self::NAME, self::RECORD );
		$this->store->set( self::NAME, '{"v":1,"current":null,"previous":null,"needs_rotation":false,"updated":1755200000}' );

		$this->assertSame(
			'{"v":1,"current":null,"previous":null,"needs_rotation":false,"updated":1755200000}',
			$this->store->get( self::NAME )
		);
	}

	/**
	 * @ticket 64789
	 */
	public function test_delete_removes_the_record() {
		$this->store->set( self::NAME, self::RECORD );
		$this->store->delete( self::NAME );

		$this->assertNull( $this->store->get( self::NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_delete_of_an_absent_record_does_not_error() {
		$this->assertTrue( $this->store->delete( self::NAME ) );
	}

	/**
	 * @ticket 64789
	 *
	 * @global wpdb $wpdb WordPress database abstraction object.
	 */
	public function test_set_stores_with_autoload_disabled() {
		global $wpdb;

		$this->store->set( self::NAME, self::RECORD );

		$autoload = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT autoload FROM $wpdb->options WHERE option_name = %s",
				WP_Secrets_Option_Store::SITE_PREFIX . self::NAME
			)
		);

		$this->assertSame( 'off', $autoload );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_names_returns_bare_names_without_the_storage_prefix() {
		$this->store->set( self::NAME, self::RECORD );

		$this->assertSame( array( self::NAME ), $this->store->list_names() );
	}

	/**
	 * The `_` in `_wp_secret_` is a LIKE wildcard and must be escaped.
	 *
	 * @ticket 64789
	 */
	public function test_list_names_does_not_match_an_unrelated_look_alike_option() {
		add_option( 'Xwp_secretY', 'should not be returned' );

		$this->assertSame( array(), $this->store->list_names() );
	}

	/**
	 * Without `esc_like()`, the trailing underscore in `_wp_secret_` would
	 * wildcard-match the "s" that begins "secrets", making this option
	 * name collide with the site-level prefix.
	 *
	 * @ticket 64789
	 */
	public function test_list_names_does_not_match_the_master_key_option() {
		add_option( '_wp_secrets_master_key', 'wrapped-master-key-record' );

		$this->assertSame( array(), $this->store->list_names() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_names_returns_empty_array_when_no_secrets_exist() {
		$this->assertSame( array(), $this->store->list_names() );
	}
}
