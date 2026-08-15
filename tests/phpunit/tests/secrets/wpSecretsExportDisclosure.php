<?php
/**
 * Tests that secrets are never exposed via the WXR export.
 *
 * Options are not exported today at all, so this is a forward guard: if
 * a future change adds options to the WXR export, this test starts
 * failing the moment it does, rather than the omission being silently
 * inherited as "safe" indefinitely.
 *
 * @group secrets
 * @group admin
 * @group export
 *
 * @covers ::export_wp
 *
 * Tests run in a separate process because export_wp() sends HTTP
 * headers via header().
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
class Tests_Secrets_WpSecretsExportDisclosure extends WP_UnitTestCase {

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	public static function wpSetUpBeforeClass( WP_UnitTest_Factory $factory ) {
		require_once ABSPATH . 'wp-admin/includes/export.php';
	}

	/**
	 * @ticket 64789
	 */
	public function test_export_never_contains_a_reserved_option_name_or_a_secret_value() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		ob_start();
		export_wp();
		$xml = ob_get_clean();

		$this->assertStringNotContainsString( self::PLAINTEXT, $xml );
		$this->assertStringNotContainsString( '_wp_secrets_master_key', $xml );
		$this->assertStringNotContainsString( '_wp_secret_' . self::NAME, $xml );
	}
}
