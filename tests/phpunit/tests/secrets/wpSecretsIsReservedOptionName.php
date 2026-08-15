<?php
/**
 * Tests for wp_secrets_is_reserved_option_name().
 *
 * @group secrets
 * @covers ::wp_secrets_is_reserved_option_name
 */
class Tests_Secrets_WpSecretsIsReservedOptionName extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 *
	 * @dataProvider data_reserved_option_names
	 *
	 * @param string $option_name Option name to check.
	 */
	public function test_recognizes_reserved_option_names( $option_name ) {
		$this->assertTrue( wp_secrets_is_reserved_option_name( $option_name ) );
	}

	/**
	 * Data provider.
	 *
	 * @return array[]
	 */
	public function data_reserved_option_names() {
		return array(
			'a site-level secret record'   => array( '_wp_secret_plugin-slug/secret-name' ),
			'the wrapped master key'       => array( '_wp_secrets_master_key' ),
			'the wrapped network root key' => array( '_wp_secrets_network_root_key' ),
		);
	}

	/**
	 * @ticket 64789
	 *
	 * @dataProvider data_non_reserved_option_names
	 *
	 * @param mixed $option_name Option name to check.
	 */
	public function test_does_not_flag_unrelated_option_names( $option_name ) {
		$this->assertFalse( wp_secrets_is_reserved_option_name( $option_name ) );
	}

	/**
	 * Data provider.
	 *
	 * @return array[]
	 */
	public function data_non_reserved_option_names() {
		return array(
			'siteurl'                       => array( 'siteurl' ),
			'a connector option'            => array( 'connectors_openai_api_key' ),
			'an unrelated underscored name' => array( '_wp_attachment_metadata' ),
			'the LIKE-trap look-alike'      => array( 'Xwp_secretY' ),
			// Stored in wp_sitemeta, never wp_options; out of scope for this predicate.
			'a network-level secret record' => array( '_wp_network_secret_plugin-slug/secret-name' ),
			'null'                          => array( null ),
			'integer'                       => array( 123 ),
		);
	}
}
