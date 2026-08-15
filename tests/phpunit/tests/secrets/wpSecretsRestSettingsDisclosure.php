<?php
/**
 * Tests that secrets are never exposed via the REST Settings API.
 *
 * @group secrets
 * @group restapi
 */
class Tests_Secrets_WpSecretsRestSettingsDisclosure extends WP_UnitTestCase {

	/**
	 * Secrets API storage is never passed to register_setting(), so it
	 * can never appear here. This asserts that fact rather than assuming
	 * it, since a future change to any of core's registered settings is
	 * exactly the kind of thing that could silently break it.
	 *
	 * @ticket 64789
	 */
	public function test_reserved_option_names_are_never_registered_settings() {
		$registered_names = array_keys( get_registered_settings() );
		$reserved_matches = array_filter( $registered_names, 'wp_secrets_is_reserved_option_name' );

		$this->assertSame( array(), array_values( $reserved_matches ) );
	}

	/**
	 * @ticket 64789
	 */
	public function test_rest_settings_endpoint_never_exposes_a_reserved_option_name() {
		wp_set_secret( 'plugin-slug/secret-name', 'sk-live-abc123-do-not-leak-me' );

		$administrator = self::factory()->user->create( array( 'role' => 'administrator' ) );
		wp_set_current_user( $administrator );

		$request  = new WP_REST_Request( 'GET', '/wp/v2/settings' );
		$response = rest_get_server()->dispatch( $request );
		$data     = $response->get_data();

		$this->assertNotEmpty( $data, 'Sanity check: the settings endpoint should expose at least the core defaults.' );

		$reserved_matches = array_filter( array_keys( $data ), 'wp_secrets_is_reserved_option_name' );

		$this->assertSame( array(), array_values( $reserved_matches ) );
	}
}
