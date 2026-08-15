<?php
/**
 * Tests for the wp_secret_changed audit hook.
 *
 * @group secrets
 * @covers ::wp_set_secret
 * @covers ::wp_delete_secret
 */

require_once dirname( __DIR__, 2 ) . '/includes/wp-secrets-assertions-trait.php';

class Tests_Secrets_WpSecretChangedAuditHook extends WP_UnitTestCase {

	use WP_Secrets_Assertions_Trait;

	const NAME      = 'plugin-slug/secret-name';
	const PLAINTEXT = 'sk-live-abc123-do-not-leak-me';

	/**
	 * @var array[] Captured ('name', 'action', 'actor_id', 'timestamp', 'old_fingerprint', 'new_fingerprint') tuples.
	 */
	private $calls = array();

	public function set_up() {
		parent::set_up();

		$this->calls = array();

		add_action( 'wp_secret_changed', array( $this, 'capture_call' ), 10, 6 );
	}

	/**
	 * Records a call to the hook for later assertions.
	 *
	 * @param string $name             Namespaced secret name.
	 * @param string $action           The action that occurred.
	 * @param int    $actor_id         The acting user's ID.
	 * @param int    $timestamp        Unix timestamp of the change.
	 * @param string $old_fingerprint  The previous fingerprint, if any.
	 * @param string $new_fingerprint  The new fingerprint, if any.
	 */
	public function capture_call( $name, $action, $actor_id, $timestamp, $old_fingerprint, $new_fingerprint ) {
		$this->calls[] = array( $name, $action, $actor_id, $timestamp, $old_fingerprint, $new_fingerprint );
	}

	/**
	 * @ticket 64789
	 */
	public function test_fires_created_on_first_write() {
		wp_set_secret( self::NAME, self::PLAINTEXT );

		$this->assertCount( 1, $this->calls );

		list( $name, $action, , , $old_fingerprint, $new_fingerprint ) = $this->calls[0];

		$this->assertSame( self::NAME, $name );
		$this->assertSame( 'created', $action );
		$this->assertSame( '', $old_fingerprint );
		$this->assertNotSame( '', $new_fingerprint );
	}

	/**
	 * @ticket 64789
	 */
	public function test_fires_updated_on_a_routine_overwrite() {
		wp_set_secret( self::NAME, 'value-a' );
		$this->calls = array();

		wp_set_secret( self::NAME, 'value-b' );

		$this->assertCount( 1, $this->calls );

		list( , $action, , , $old_fingerprint, $new_fingerprint ) = $this->calls[0];

		$this->assertSame( 'updated', $action );
		$this->assertNotSame( '', $old_fingerprint );
		$this->assertNotSame( $old_fingerprint, $new_fingerprint );
	}

	/**
	 * @ticket 64789
	 */
	public function test_fires_rotated_when_the_existing_record_needed_rotation() {
		wp_set_secret( self::NAME, 'value-a' );

		$option_name              = WP_Secrets_Option_Store::SITE_PREFIX . self::NAME;
		$record                   = json_decode( get_option( $option_name ), true );
		$record['needs_rotation'] = true;
		update_option( $option_name, wp_json_encode( $record ), false );

		$this->calls = array();

		wp_set_secret( self::NAME, 'value-b' );

		$this->assertCount( 1, $this->calls );
		$this->assertSame( 'rotated', $this->calls[0][1] );
	}

	/**
	 * @ticket 64789
	 */
	public function test_fires_deleted_on_delete() {
		wp_set_secret( self::NAME, self::PLAINTEXT );
		$fingerprint_before_delete = wp_get_secret( self::NAME )->get_fingerprint();
		$this->calls               = array();

		wp_delete_secret( self::NAME );

		$this->assertCount( 1, $this->calls );

		list( , $action, , , $old_fingerprint, $new_fingerprint ) = $this->calls[0];

		$this->assertSame( 'deleted', $action );
		$this->assertSame( $fingerprint_before_delete, $old_fingerprint );
		$this->assertSame( '', $new_fingerprint );
	}

	/**
	 * @ticket 64789
	 */
	public function test_no_plaintext_in_any_hook_argument() {
		wp_set_secret( self::NAME, 'value-a' );
		wp_set_secret( self::NAME, 'value-b' ); // 'updated', also demotes 'value-a'.
		wp_delete_secret( self::NAME );

		$this->assertCount( 3, $this->calls );
		$this->assertDoesNotContainSecret( 'value-a', $this->calls );
		$this->assertDoesNotContainSecret( 'value-b', $this->calls );
	}
}
