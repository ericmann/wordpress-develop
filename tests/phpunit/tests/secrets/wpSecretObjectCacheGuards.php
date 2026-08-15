<?php
/**
 * Tests that plaintext secret values cannot enter the object cache.
 *
 * @group secrets
 * @covers WP_Secret::__clone
 * @covers ::wp_set_secret
 * @covers ::wp_get_secret
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpSecretObjectCacheGuards extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	/**
	 * @ticket 64789
	 */
	public function test_wp_cache_set_of_a_wp_secret_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, 'fingerprint' );

		$this->expectException( LogicException::class );
		wp_cache_set( 'test-key', $secret, 'test-group' );
	}

	/**
	 * @ticket 64789
	 */
	public function test_wp_cache_add_of_a_wp_secret_throws() {
		$secret = new WP_Secret( self::NAME, self::PLAINTEXT, 'fingerprint' );

		$this->expectException( LogicException::class );
		wp_cache_add( 'test-key', $secret, 'test-group' );
	}

	/**
	 * WP_Object_Cache::set() clones any object value before storing it,
	 * so a wp_cache_set() call that is never reached by the exception
	 * (for example, from a future code path) still must not leave a
	 * plaintext value behind in the group it targeted.
	 *
	 * @ticket 64789
	 *
	 * @global WP_Object_Cache $wp_object_cache Object cache global instance.
	 */
	public function test_no_plaintext_in_any_cache_group_after_set_and_get() {
		global $wp_object_cache;

		wp_set_secret( self::NAME, self::PLAINTEXT );
		wp_get_secret( self::NAME );

		$this->assertDoesNotContainSecret( self::PLAINTEXT, $wp_object_cache->cache );
	}

	/**
	 * @ticket 64789
	 *
	 * @global WP_Object_Cache $wp_object_cache Object cache global instance.
	 */
	public function test_no_plaintext_in_any_cache_group_after_version_slot_demotion() {
		global $wp_object_cache;

		wp_set_secret( self::NAME, 'value-a' );
		wp_set_secret( self::NAME, 'value-b' ); // Demotes 'value-a' to the previous slot.

		$this->assertDoesNotContainSecret( 'value-a', $wp_object_cache->cache );
		$this->assertDoesNotContainSecret( 'value-b', $wp_object_cache->cache );
	}
}
