<?php
/**
 * Tests for the manage_secrets upgrade routine's version gate.
 *
 * @group secrets
 * @group upgrade
 * @covers ::upgrade_all
 * @covers ::upgrade_720
 */
class Tests_Secrets_WpSecretsUpgradeGate extends WP_UnitTestCase {

	/**
	 * A site that was fully up to date immediately before this change shipped
	 * stores $wp_db_version's old value verbatim, so the gate must trigger for
	 * a $wp_current_db_version equal to that old value, not just below it.
	 *
	 * @ticket 64789
	 */
	public function test_upgrade_720_runs_for_a_site_at_the_last_pre_720_db_version() {
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		$administrator = get_role( 'administrator' );
		$administrator->remove_cap( 'manage_secrets' );

		$previous_db_version = get_option( 'db_version' );
		update_option( 'db_version', 61833 );

		upgrade_all();

		update_option( 'db_version', $previous_db_version );

		$this->assertTrue( get_role( 'administrator' )->has_cap( 'manage_secrets' ) );
	}
}
