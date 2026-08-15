<?php
/**
 * Tests for wp_set_secret() and wp_get_secret().
 *
 * @group secrets
 * @covers ::wp_set_secret
 * @covers ::wp_get_secret
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpSetSecretAndWpGetSecret extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	/**
	 * @ticket 64789
	 */
	public function test_set_returns_true_on_success() {
		$this->assertTrue( wp_set_secret( self::NAME, self::PLAINTEXT ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_round_trip() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$secret = wp_get_secret( self::NAME );

		$this->assertInstanceOf( WP_Secret::class, $secret );
		$this->assertSame( self::PLAINTEXT, $secret->reveal() );
		$this->assertSame( self::NAME, $secret->get_name() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_get_returns_null_when_the_secret_does_not_exist() {
		$this->assertNull( wp_get_secret( self::NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_get_returns_wp_error_when_the_stored_record_does_not_decrypt() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$option_name             = WP_Secrets_Option_Store::SITE_PREFIX . self::NAME;
		$record                  = json_decode( get_option( $option_name ), true );
		$ciphertext              = base64_decode( $record['current']['ct'], true );
		$ciphertext[0]           = chr( ord( $ciphertext[0] ) ^ 0xFF );
		$record['current']['ct'] = base64_encode( $ciphertext );
		update_option( $option_name, wp_json_encode( $record ), false );

		$actual = wp_get_secret( self::NAME );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_decryption_failed', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 *
	 * @dataProvider data_empty_or_non_string_values
	 *
	 * @param mixed $value Value to attempt to store.
	 */
	public function test_set_rejects_empty_or_non_string_values( $value ) {
		$actual = wp_set_secret( self::NAME, $value );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_empty_value', $actual->get_error_code() );
	}

	/**
	 * Data provider.
	 *
	 * @return array[]
	 */
	public function data_empty_or_non_string_values() {
		return array(
			'empty string' => array( '' ),
			'null'         => array( null ),
			'integer'      => array( 123 ),
			'array'        => array( array( 'not', 'a', 'string' ) ),
		);
	}

	/**
	 * @ticket 64789
	 */
	public function test_set_rejects_an_invalid_name() {
		$actual = wp_set_secret( 'Not A Valid Name', self::PLAINTEXT );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_invalid_name', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_get_rejects_an_invalid_name() {
		$actual = wp_get_secret( 'Not A Valid Name' );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_invalid_name', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 *
	 * @global wpdb $wpdb WordPress database abstraction object.
	 */
	public function test_the_stored_option_row_never_contains_the_plaintext_value() {
		global $wpdb;

		wp_set_secret( self::NAME, self::PLAINTEXT );

		$option_name = WP_Secrets_Option_Store::SITE_PREFIX . self::NAME;
		$raw_row     = $wpdb->get_var( $wpdb->prepare( "SELECT option_value FROM $wpdb->options WHERE option_name = %s", $option_name ) );

		$this->assertDoesNotContainSecret( self::PLAINTEXT, $raw_row );
	}

	/**
	 * @ticket 64789
	 */
	public function test_fingerprint_is_stable_for_the_same_value() {
		wp_set_secret( self::NAME, self::PLAINTEXT );
		$first = wp_get_secret( self::NAME )->get_fingerprint();

		wp_set_secret( self::NAME, self::PLAINTEXT );
		$second = wp_get_secret( self::NAME )->get_fingerprint();

		$this->assertSame( $first, $second );
		$this->assertMatchesRegularExpression( '/^[0-9a-f]{32}$/', $first );
	}
}
