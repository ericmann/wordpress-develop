<?php
/**
 * Tests for the network-level secret functions and per-site subkey derivation.
 *
 * @group secrets
 * @group multisite
 * @covers ::wp_set_network_secret
 * @covers ::wp_get_network_secret
 * @covers ::wp_delete_network_secret
 * @covers ::wp_list_network_secrets
 * @covers ::wp_secrets_resolve_master_key
 */
class Tests_Secrets_WpSecretsNetworkFunctions extends WP_UnitTestCase {

	const NAME = 'plugin-slug/secret-name';

	/**
	 * On single site there is no separate network keyspace: the network
	 * functions proxy directly to the site functions.
	 *
	 * @ticket 64789
	 *
	 * @group ms-excluded
	 */
	public function test_network_functions_proxy_to_site_functions_on_single_site() {
		wp_set_network_secret( self::NAME, 'a-value' );

		$this->assertSame( 'a-value', wp_get_secret( self::NAME )->reveal() );
		$this->assertSame( 'a-value', wp_get_network_secret( self::NAME )->reveal() );

		$this->assertTrue( wp_delete_network_secret( self::NAME ) );
		$this->assertNull( wp_get_secret( self::NAME ) );
	}

	/**
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_network_secret_round_trips_and_is_listed() {
		wp_set_network_secret( self::NAME, 'a-network-value' );

		$secret = wp_get_network_secret( self::NAME );
		$this->assertInstanceOf( WP_Secret::class, $secret );
		$this->assertSame( 'a-network-value', $secret->reveal() );

		$list = wp_list_network_secrets();
		$this->assertCount( 1, $list );
		$this->assertSame( self::NAME, $list[0]['name'] );

		$this->assertTrue( wp_delete_network_secret( self::NAME ) );
		$this->assertNull( wp_get_network_secret( self::NAME ) );
	}

	/**
	 * No implicit network fallback on multisite: site and network
	 * secrets are separate keyspaces, checked independently.
	 *
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_site_and_network_keyspaces_are_isolated_with_no_implicit_fallback() {
		wp_set_secret( self::NAME, 'site-value' );

		$this->assertNull( wp_get_network_secret( self::NAME ) );

		wp_set_network_secret( self::NAME, 'network-value' );

		// Both now exist, under the same name, and do not cross-contaminate.
		$this->assertSame( 'site-value', wp_get_secret( self::NAME )->reveal() );
		$this->assertSame( 'network-value', wp_get_network_secret( self::NAME )->reveal() );

		wp_delete_network_secret( self::NAME );

		// Deleting the network copy must not touch the site copy.
		$this->assertSame( 'site-value', wp_get_secret( self::NAME )->reveal() );
	}

	/**
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_master_key_derivation_is_deterministic_for_the_same_site() {
		$this->assertSame( wp_secrets_resolve_master_key(), wp_secrets_resolve_master_key() );
	}

	/**
	 * Individual sites derive their master key from the shared network
	 * root key and their own site ID, so two sites on the same network
	 * end up with different, but each internally consistent, master keys.
	 *
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_master_key_derivation_differs_across_sites() {
		$site_b = self::factory()->blog->create();

		$master_key_for_main_site = wp_secrets_resolve_master_key();

		switch_to_blog( $site_b );
		$master_key_for_site_b = wp_secrets_resolve_master_key();
		restore_current_blog();

		$this->assertNotSame( $master_key_for_main_site, $master_key_for_site_b );

		// Each site's own secrets remain independently readable.
		wp_set_secret( self::NAME, 'main-site-value' );

		switch_to_blog( $site_b );
		wp_set_secret( self::NAME, 'site-b-value' );
		$this->assertSame( 'site-b-value', wp_get_secret( self::NAME )->reveal() );
		restore_current_blog();

		$this->assertSame( 'main-site-value', wp_get_secret( self::NAME )->reveal() );
	}

	/**
	 * Network secrets are encrypted directly under the network root key,
	 * not a further per-site derivation: there is only one network
	 * keyspace, so there is nothing to derive a subkey for.
	 *
	 * @ticket 64789
	 *
	 * @group ms-required
	 */
	public function test_network_master_key_is_the_network_root_key_itself() {
		$this->assertSame(
			( new WP_Secrets_Key_Manager( null, true ) )->get_master_key(),
			wp_secrets_resolve_master_key( true )
		);
	}
}
