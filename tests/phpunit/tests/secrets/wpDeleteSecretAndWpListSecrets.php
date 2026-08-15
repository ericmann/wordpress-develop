<?php
/**
 * Tests for wp_delete_secret() and wp_list_secrets().
 *
 * @group secrets
 * @covers ::wp_delete_secret
 * @covers ::wp_list_secrets
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpDeleteSecretAndWpListSecrets extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	/**
	 * @ticket 64789
	 */
	public function test_delete_removes_both_slots() {
		wp_set_secret( self::NAME, 'value-a' );
		wp_set_secret( self::NAME, 'value-b' ); // Populates both current and previous.

		$this->assertTrue( wp_delete_secret( self::NAME ) );
		$this->assertNull( wp_get_secret( self::NAME ) );
		$this->assertFalse( get_option( WP_Secrets_Option_Store::SITE_PREFIX . self::NAME ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_delete_returns_error_when_the_secret_does_not_exist() {
		$actual = wp_delete_secret( self::NAME );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_not_found', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_delete_rejects_an_invalid_name() {
		$actual = wp_delete_secret( 'Not A Valid Name' );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_invalid_name', $actual->get_error_code() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_returns_empty_array_when_no_secrets_exist() {
		$this->assertSame( array(), wp_list_secrets() );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_returns_metadata_only_never_a_value() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$results = wp_list_secrets();

		$this->assertCount( 1, $results );
		$this->assertSame(
			array( 'name', 'fingerprint', 'previous_fingerprint', 'created', 'updated', 'needs_rotation' ),
			array_keys( $results[0] )
		);
		$this->assertSame( self::NAME, $results[0]['name'] );
		$this->assertDoesNotContainSecret( self::PLAINTEXT, $results );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_needs_rotation_defaults_to_false() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$results = wp_list_secrets();

		$this->assertFalse( $results[0]['needs_rotation'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_has_no_previous_fingerprint_before_a_second_write() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$results = wp_list_secrets();

		$this->assertSame( '', $results[0]['previous_fingerprint'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_includes_previous_fingerprint_after_a_second_write() {
		wp_set_secret( self::NAME, 'value-a' );
		$fingerprint_a = wp_get_secret( self::NAME )->get_fingerprint();

		wp_set_secret( self::NAME, 'value-b' );

		$results = wp_list_secrets();

		$this->assertSame( $fingerprint_a, $results[0]['previous_fingerprint'] );
		$this->assertNotSame( $results[0]['fingerprint'], $results[0]['previous_fingerprint'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_restricts_results_to_the_given_namespace() {
		wp_set_secret( 'namespace-one/secret', 'value-1' );
		wp_set_secret( 'namespace-two/secret', 'value-2' );

		$results = wp_list_secrets( 'namespace-one' );

		$this->assertCount( 1, $results );
		$this->assertSame( 'namespace-one/secret', $results[0]['name'] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_with_no_namespace_returns_all_namespaces() {
		wp_set_secret( 'namespace-one/secret', 'value-1' );
		wp_set_secret( 'namespace-two/secret', 'value-2' );

		$results = wp_list_secrets();

		$this->assertCount( 2, $results );
	}
}
