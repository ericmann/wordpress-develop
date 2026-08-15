<?php
/**
 * Tests for the Secrets admin screen.
 *
 * @group secrets
 * @group admin
 * @covers WP_Secrets_List_Table
 * @covers ::wp_secrets_render_screen
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpSecretsAdminScreen extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	public static function wpSetUpBeforeClass( WP_UnitTest_Factory $factory ) {
		require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
		require_once ABSPATH . 'wp-admin/includes/list-table.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-secrets-list-table.php';
		require_once ABSPATH . 'wp-admin/includes/template.php';
		require_once ABSPATH . 'wp-admin/includes/secrets.php';
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_table_renders_the_name_and_fingerprint() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$list_table = _get_list_table( 'WP_Secrets_List_Table' );
		$list_table->prepare_items();

		ob_start();
		$list_table->display();
		$output = ob_get_clean();

		$fingerprint = wp_get_secret( self::NAME )->get_fingerprint();

		$this->assertStringContainsString( self::NAME, $output );
		$this->assertStringContainsString( $fingerprint, $output );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_table_never_renders_a_value() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$list_table = _get_list_table( 'WP_Secrets_List_Table' );
		$list_table->prepare_items();

		ob_start();
		$list_table->display();
		$output = ob_get_clean();

		$this->assertDoesNotContainSecret( self::PLAINTEXT, $output );
	}

	/**
	 * @ticket 64789
	 */
	public function test_list_table_shows_needs_rotation_status() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$option_name              = WP_Secrets_Option_Store::SITE_PREFIX . self::NAME;
		$record                   = json_decode( get_option( $option_name ), true );
		$record['needs_rotation'] = true;
		update_option( $option_name, wp_json_encode( $record ), false );

		$list_table = _get_list_table( 'WP_Secrets_List_Table' );
		$list_table->prepare_items();

		ob_start();
		$list_table->display();
		$output = ob_get_clean();

		$this->assertStringContainsString( 'Needs rotation', $output );
	}

	/**
	 * @ticket 64789
	 */
	public function test_admin_screen_is_gated_on_manage_secrets() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'subscriber' ) ) );

		$this->expectException( WPDieException::class );

		wp_secrets_render_admin_page();
	}

	/**
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_network_admin_screen_is_gated_on_manage_network_secrets() {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		$this->expectException( WPDieException::class );

		wp_secrets_render_network_admin_page();
	}

	/**
	 * @ticket 64789
	 */
	public function test_admin_screen_renders_for_an_administrator_without_a_value() {
		wp_set_secret( self::NAME, self::PLAINTEXT );
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );

		ob_start();
		wp_secrets_render_admin_page();
		$output = ob_get_clean();

		$this->assertStringContainsString( self::NAME, $output );
		$this->assertDoesNotContainSecret( self::PLAINTEXT, $output );
	}
}
