<?php
/**
 * Tests for wp_import_secret_from_option().
 *
 * @group secrets
 * @covers ::wp_import_secret_from_option
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpImportSecretFromOption extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const OPTION_NAME = 'my_plugin_api_key';
	const SECRET_NAME = 'my-plugin/api-key';
	const PLAINTEXT   = 'sk-live-abc123-do-not-leak-me';

	/**
	 * @ticket 64789
	 */
	public function test_option_is_removed_after_import() {
		add_option( self::OPTION_NAME, self::PLAINTEXT );

		wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$this->assertFalse( get_option( self::OPTION_NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_needs_rotation_is_set() {
		add_option( self::OPTION_NAME, self::PLAINTEXT );

		wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$list = wp_list_secrets();

		$this->assertCount( 1, $list );
		$this->assertTrue( $list[0]['needs_rotation'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_value_is_preserved() {
		add_option( self::OPTION_NAME, self::PLAINTEXT );

		$actual = wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$this->assertTrue( $actual );
		$this->assertSame( self::PLAINTEXT, wp_get_secret( self::SECRET_NAME )->reveal() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_returns_error_when_option_does_not_exist() {
		$actual = wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_not_found', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_returns_error_when_option_value_is_empty() {
		add_option( self::OPTION_NAME, '' );

		$actual = wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_empty_value', $actual->get_error_code() );

		// Nothing should have been consumed on failure.
		$this->assertSame( '', get_option( self::OPTION_NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_fires_wp_secret_changed_as_a_creation() {
		add_option( self::OPTION_NAME, self::PLAINTEXT );

		$calls = array();
		add_action(
			'wp_secret_changed',
			static function ( $name, $action ) use ( &$calls ) {
				$calls[] = array( $name, $action );
			},
			10,
			2
		);

		wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$this->assertSame( array( array( self::SECRET_NAME, 'created' ) ), $calls );
	}

	/**
	 * @ticket 64789
	 *
	 * @global wpdb $wpdb WordPress database abstraction object.
	 */
	public function test_the_plaintext_value_does_not_leak_into_the_stored_record() {
		global $wpdb;

		add_option( self::OPTION_NAME, self::PLAINTEXT );

		wp_import_secret_from_option( self::OPTION_NAME, self::SECRET_NAME );

		$option_name = WP_Secrets_Option_Store::SITE_PREFIX . self::SECRET_NAME;
		$raw_row     = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM $wpdb->options WHERE option_name = %s", $option_name ) );

		$this->assertDoesNotContainSecret( self::PLAINTEXT, $raw_row );
	}
}
