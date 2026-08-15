<?php
/**
 * Tests for the Secrets API's Site Health tests.
 *
 * @group secrets
 * @covers WP_Site_Health::get_test_secrets_undecryptable
 * @covers WP_Site_Health::get_test_secrets_salts_fallback
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpSecretsSiteHealth extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	public static function wpSetUpBeforeClass( WP_UnitTest_Factory $factory ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-site-health.php';
	}

	/**
	 * @ticket 64789
	 */
	public function test_undecryptable_is_good_when_no_secrets_exist() {
		$result = WP_Site_Health::get_instance()->get_test_secrets_undecryptable();

		$this->assertSame( 'good', $result['status'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_undecryptable_is_good_when_all_secrets_decrypt() {
		wp_set_secret( self::NAME, self::PLAINTEXT );
		wp_set_secret( 'plugin-slug/other-secret', 'another-value' );

		$result = WP_Site_Health::get_instance()->get_test_secrets_undecryptable();

		$this->assertSame( 'good', $result['status'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_undecryptable_is_critical_when_a_secret_cannot_decrypt() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$option_name             = WP_Secrets_Option_Store::SITE_PREFIX . self::NAME;
		$record                  = json_decode( get_option( $option_name ), true );
		$ciphertext              = base64_decode( $record['current']['ct'], true );
		$ciphertext[0]           = chr( ord( $ciphertext[0] ) ^ 0xFF );
		$record['current']['ct'] = base64_encode( $ciphertext );
		update_option( $option_name, wp_json_encode( $record ), false );

		$result = WP_Site_Health::get_instance()->get_test_secrets_undecryptable();

		$this->assertSame( 'critical', $result['status'] );
		$this->assertStringContainsString( '1', $result['description'] );
		$this->assertDoesNotContainSecret( self::PLAINTEXT, $result );
	}

	/**
	 * @ticket 64789
	 */
	public function test_salts_fallback_is_recommended_when_constant_is_not_defined() {
		$this->assertFalse( defined( 'WP_SECRETS_KEY' ), 'This test assumes WP_SECRETS_KEY is not defined in the base test environment.' );

		$result = WP_Site_Health::get_instance()->get_test_secrets_salts_fallback();

		$this->assertSame( 'recommended', $result['status'] );
	}

	/**
	 * @ticket 64789
	 *
	 * @runInSeparateProcess
	 * @preserveGlobalState disabled
	 */
	public function test_salts_fallback_is_good_when_constant_is_defined() {
		define( 'WP_SECRETS_KEY', base64_encode( random_bytes( 32 ) ) );

		$result = WP_Site_Health::get_instance()->get_test_secrets_salts_fallback();

		$this->assertSame( 'good', $result['status'] );
	}
}
