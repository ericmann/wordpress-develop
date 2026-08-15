<?php
/**
 * Tests for wp_secrets_validate_name().
 *
 * @group secrets
 * @covers ::wp_secrets_validate_name
 */
class Tests_Secrets_WpSecretsValidateName extends WP_UnitTestCase {

	/**
	 * @ticket 64789
	 *
	 * @dataProvider data_valid_names
	 *
	 * @param string $name Secret name to validate.
	 */
	public function test_accepts_valid_names( $name ) {
		$this->assertTrue( wp_secrets_validate_name( $name ) );
	}

	/**
	 * Data provider.
	 *
	 * @return array[]
	 */
	public function data_valid_names() {
		return array(
			'minimal single-char segments' => array( 'a/a' ),
			'hyphenated namespace'         => array( 'plugin-slug/secret-name' ),
			'underscored segments'         => array( 'my_plugin/my_secret' ),
			'digits'                       => array( 'plugin2/secret2' ),
			'internal hyphen and digit'    => array( 'a-b-c/d1-e2' ),
			'exactly 160 bytes'            => array( str_repeat( 'a', 79 ) . '/' . str_repeat( 'b', 80 ) ),
		);
	}

	/**
	 * @ticket 64789
	 *
	 * @dataProvider data_invalid_names
	 *
	 * @param mixed $name Secret name to validate.
	 */
	public function test_rejects_invalid_names( $name ) {
		$actual = wp_secrets_validate_name( $name );

		$this->assertWPError( $actual );
		$this->assertSame( 'secret_invalid_name', $actual->get_error_code() );
	}

	/**
	 * Data provider.
	 *
	 * @return array[]
	 */
	public function data_invalid_names() {
		return array(
			'empty string'                  => array( '' ),
			'no slash'                      => array( 'pluginsecret' ),
			'two slashes'                   => array( 'a/b/c' ),
			'trailing slash, no name'       => array( 'a/b/' ),
			'uppercase namespace'           => array( 'Plugin/secret' ),
			'uppercase name'                => array( 'plugin/Secret' ),
			'leading hyphen in namespace'   => array( '-plugin/secret' ),
			'trailing hyphen in namespace'  => array( 'plugin-/secret' ),
			'leading underscore in name'    => array( 'plugin/_secret' ),
			'trailing underscore in name'   => array( 'plugin/secret_' ),
			'empty namespace segment'       => array( '/secret' ),
			'empty name segment'            => array( 'plugin/' ),
			'invalid punctuation character' => array( 'plugin!/secret' ),
			'space character'               => array( 'plugin secret/name' ),
			'over the 160 byte ceiling'     => array( str_repeat( 'a', 80 ) . '/' . str_repeat( 'b', 80 ) ),
			'non-string null'               => array( null ),
			'non-string integer'            => array( 123 ),
			'non-string array'              => array( array( 'plugin/secret' ) ),
		);
	}
}
