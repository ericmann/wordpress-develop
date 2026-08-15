<?php
/**
 * Trait for asserting that plaintext secret values do not leak.
 *
 * @package WordPress
 * @subpackage Secrets
 */

/**
 * Trait providing a shared negative assertion for the Secrets API test suite.
 *
 * For every code path that touches a plaintext secret value, the valuable
 * assertion is not that the value round-trips correctly (that is the easy
 * case), but that it does not also show up somewhere it should not: a mock
 * store's arguments, a hook's arguments, an admin screen, a `wp_list_secrets()`
 * result, a `var_dump()` capture.
 *
 * @since 7.2.0
 */
trait WP_Secrets_Assertions_Trait {

	/**
	 * Asserts that a plaintext secret value does not appear anywhere in a haystack.
	 *
	 * The haystack may be a string, or an array searched recursively (both
	 * keys and values). Other types are not descended into: this assertion
	 * is for option rows, hook arguments, and mock call arguments, not for
	 * reaching into the private internals of an opaque object.
	 *
	 * @since 7.2.0
	 *
	 * @param string $needle   The plaintext secret value to search for.
	 * @param mixed  $haystack The value to search within.
	 * @param string $message  Optional. Failure message.
	 */
	public function assertDoesNotContainSecret( $needle, $haystack, $message = '' ) { // phpcs:ignore WordPress.NamingConventions.ValidFunctionName.MethodNameInvalid
		$this->assertNotSame( '', $needle, 'The needle passed to assertDoesNotContainSecret() must not be empty; an empty needle is trivially found in every haystack.' );

		$this->assertFalse(
			$this->secret_assertions_trait_haystack_contains( $needle, $haystack ),
			'' !== $message ? $message : 'Failed asserting that a plaintext secret value does not appear in the given haystack.'
		);
	}

	/**
	 * Recursively searches a haystack for a plaintext needle.
	 *
	 * @since 7.2.0
	 *
	 * @param string $needle   The plaintext secret value to search for.
	 * @param mixed  $haystack The value to search within.
	 * @return bool Whether the needle was found.
	 */
	private function secret_assertions_trait_haystack_contains( $needle, $haystack ) {
		if ( is_array( $haystack ) ) {
			foreach ( $haystack as $key => $value ) {
				if ( $this->secret_assertions_trait_haystack_contains( $needle, $key ) ) {
					return true;
				}

				if ( $this->secret_assertions_trait_haystack_contains( $needle, $value ) ) {
					return true;
				}
			}

			return false;
		}

		if ( is_scalar( $haystack ) ) {
			return false !== strpos( (string) $haystack, $needle );
		}

		return false;
	}
}
