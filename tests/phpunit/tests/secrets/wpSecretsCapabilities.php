<?php
/**
 * Tests for the manage_secrets and manage_network_secrets capabilities.
 *
 * @group secrets
 * @group capabilities
 * @covers ::map_meta_cap
 */
class Tests_Secrets_WpSecretsCapabilities extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 */
	public function test_administrator_has_manage_secrets() {
		$administrator = self::factory()->user->create( array( 'role' => 'administrator' ) );

		$this->assertTrue( user_can( $administrator, 'manage_secrets' ) );
	}

	/**
	 * @ticket 64789
	 *
	 * @dataProvider data_roles_without_manage_secrets
	 *
	 * @param string $role Role to test.
	 */
	public function test_other_roles_do_not_have_manage_secrets( $role ) {
		$user = self::factory()->user->create( array( 'role' => $role ) );

		$this->assertFalse( user_can( $user, 'manage_secrets' ) );
	}

	/**
	 * Data provider.
	 *
	 * @return array[]
	 */
	public function data_roles_without_manage_secrets() {
		return array(
			'subscriber'  => array( 'subscriber' ),
			'contributor' => array( 'contributor' ),
			'author'      => array( 'author' ),
			'editor'      => array( 'editor' ),
		);
	}

	/**
	 * On single site, the multisite super-admin blanket grant in
	 * WP_User::has_cap() never applies, so manage_network_secrets is not
	 * granted to anyone at all - not even an administrator.
	 *
	 * @ticket 64789
	 *
	 * @group ms-excluded
	 */
	public function test_manage_network_secrets_is_not_granted_on_single_site() {
		$administrator = self::factory()->user->create( array( 'role' => 'administrator' ) );

		$this->assertFalse( user_can( $administrator, 'manage_network_secrets' ) );
	}

	/**
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_manage_network_secrets_is_super_admin_only() {
		$super_admin = self::factory()->user->create( array( 'role' => 'administrator' ) );
		$site_admin  = self::factory()->user->create( array( 'role' => 'administrator' ) );

		grant_super_admin( $super_admin );

		$this->assertTrue( user_can( $super_admin, 'manage_network_secrets' ) );
		$this->assertFalse( user_can( $site_admin, 'manage_network_secrets' ) );
	}
}
