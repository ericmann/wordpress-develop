<?php
/**
 * Secrets API: WP_Secret class.
 *
 * @package WordPress
 * @subpackage Secrets
 * @since 7.2.0
 */

/**
 * Represents a single decrypted secret value.
 *
 * Instances are created by the Secrets API after a stored record has
 * been successfully decrypted. The only way to obtain the plaintext is
 * to call reveal() explicitly, so that every place a secret value
 * leaves this object and enters the rest of a codebase is greppable.
 *
 * This class cannot be serialized in any form, in either direction. A
 * WP_Secret that could survive a round trip through the object cache or
 * a session would defeat the reason its value was encrypted at rest.
 *
 * @since 7.2.0
 */
final class WP_Secret implements JsonSerializable {

	/**
	 * The decrypted secret value.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	private $value;

	/**
	 * The secret's namespaced name.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	private $name;

	/**
	 * The keyed fingerprint of the secret value.
	 *
	 * @since 7.2.0
	 * @var string
	 */
	private $fingerprint;

	/**
	 * Constructor.
	 *
	 * @since 7.2.0
	 *
	 * @param string $name        Namespaced secret name.
	 * @param string $value       Decrypted secret value.
	 * @param string $fingerprint Keyed fingerprint of the secret value.
	 */
	public function __construct( $name, $value, $fingerprint ) {
		$this->name        = $name;
		$this->value       = $value;
		$this->fingerprint = $fingerprint;
	}

	/**
	 * Returns the decrypted secret value.
	 *
	 * This is the only way to obtain the plaintext. The method is not
	 * overloaded for anything else, so every place a secret's value is
	 * pulled out of the Secrets API can be found with a single grep for
	 * `->reveal()`.
	 *
	 * @since 7.2.0
	 *
	 * @return string The decrypted secret value.
	 */
	public function reveal() {
		return $this->value;
	}

	/**
	 * Returns the secret's namespaced name.
	 *
	 * @since 7.2.0
	 *
	 * @return string The secret's namespaced name.
	 */
	public function get_name() {
		return $this->name;
	}

	/**
	 * Returns the keyed fingerprint of the secret value.
	 *
	 * @since 7.2.0
	 *
	 * @return string The keyed fingerprint of the secret value.
	 */
	public function get_fingerprint() {
		return $this->fingerprint;
	}

	/**
	 * Redacts the secret value for string interpolation and most log paths.
	 *
	 * @since 7.2.0
	 *
	 * @return string A redacted string representation.
	 */
	public function __toString() {
		return '[redacted secret: ' . $this->name . ']';
	}

	/**
	 * Redacts the secret value for var_dump().
	 *
	 * `print_r()` and `var_export()` cannot be intercepted for private
	 * properties in a way that redacts them; `print_r()` will still show
	 * `[value:WP_Secret:private] => the-plaintext-value`. That is a known
	 * limitation of this class, not a claim that every debug output path
	 * is masked. It is the reason `->reveal()` is the documented, greppable
	 * way to obtain the value, rather than a claim that other paths are
	 * impossible.
	 *
	 * @since 7.2.0
	 *
	 * @return array Redacted representation for var_dump().
	 */
	public function __debugInfo() {
		return array(
			'name'        => $this->name,
			'value'       => '[redacted]',
			'fingerprint' => $this->fingerprint,
		);
	}

	/**
	 * Redacts the secret value for json_encode().
	 *
	 * @since 7.2.0
	 *
	 * @return array Redacted representation for json_encode().
	 */
	public function jsonSerialize() {
		return array(
			'name'  => $this->name,
			'value' => '[redacted]',
		);
	}

	/**
	 * Prevents serialization via __sleep()/__wakeup().
	 *
	 * @since 7.2.0
	 *
	 * @throws LogicException Always.
	 */
	public function __sleep() {
		throw new LogicException( 'WP_Secret cannot be serialized.' );
	}

	/**
	 * Prevents unserialization via __sleep()/__wakeup().
	 *
	 * @since 7.2.0
	 *
	 * @throws LogicException Always.
	 */
	public function __wakeup() {
		throw new LogicException( 'WP_Secret cannot be unserialized.' );
	}

	/**
	 * Prevents serialization via __serialize()/__unserialize().
	 *
	 * PHP prefers this pair over __sleep()/__wakeup() when both are
	 * present, but the older pair still fires on some serialization
	 * paths (including, historically, some object cache backends), so
	 * both pairs must throw.
	 *
	 * @since 7.2.0
	 *
	 * @throws LogicException Always.
	 */
	public function __serialize() {
		throw new LogicException( 'WP_Secret cannot be serialized.' );
	}

	/**
	 * Prevents unserialization via __serialize()/__unserialize().
	 *
	 * @since 7.2.0
	 *
	 * @param array $data Unused.
	 * @throws LogicException Always.
	 */
	public function __unserialize( $data ) {
		throw new LogicException( 'WP_Secret cannot be unserialized.' );
	}

	/**
	 * Prevents cloning.
	 *
	 * WP_Object_Cache::set() clones any object value before storing it.
	 * Without this guard, that clone would succeed silently and a
	 * WP_Secret - plaintext included - would end up sitting in the
	 * object cache, which on shared hosting is often infrastructure
	 * shared with other tenants.
	 *
	 * @since 7.2.0
	 *
	 * @throws LogicException Always.
	 */
	public function __clone() {
		throw new LogicException( 'WP_Secret cannot be cloned.' );
	}
}
