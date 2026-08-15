<?php
/**
 * List Table API: WP_Secrets_List_Table class
 *
 * @package WordPress
 * @subpackage Administration
 * @since 7.2.0
 */

/**
 * Class for displaying the list of stored secrets.
 *
 * Metadata only: name, fingerprint, created, updated, and whether the
 * secret needs rotation. There is no reveal, no edit-in-place, and no
 * copy button - only add/overwrite (via a separate form) and delete.
 *
 * @since 7.2.0
 *
 * @see WP_List_Table
 */
class WP_Secrets_List_Table extends WP_List_Table {

	/**
	 * Whether this table lists network-level secrets.
	 *
	 * @since 7.2.0
	 * @var bool
	 */
	private $network;

	/**
	 * Constructor.
	 *
	 * @since 7.2.0
	 *
	 * @param array $args Optional. Array of arguments, plus a `network` key. Default empty array.
	 */
	public function __construct( $args = array() ) {
		$this->network = ! empty( $args['network'] );

		parent::__construct(
			array(
				'plural'   => 'secrets',
				'singular' => 'secret',
				'ajax'     => false,
				'screen'   => isset( $args['screen'] ) ? $args['screen'] : null,
			)
		);
	}

	/**
	 * Gets the list of columns.
	 *
	 * @since 7.2.0
	 *
	 * @return string[] Array of column titles keyed by their column name.
	 */
	public function get_columns() {
		return array(
			'name'           => __( 'Name' ),
			'fingerprint'    => __( 'Fingerprint' ),
			'created'        => __( 'Created' ),
			'updated'        => __( 'Updated' ),
			'needs_rotation' => __( 'Status' ),
			'delete'         => __( 'Delete' ),
		);
	}

	/**
	 * Prepares the list of items for displaying.
	 *
	 * @since 7.2.0
	 */
	public function prepare_items() {
		$secrets = $this->network ? wp_list_network_secrets() : wp_list_secrets();

		$this->items = is_wp_error( $secrets ) ? array() : $secrets;
	}

	/**
	 * Handles the name column output.
	 *
	 * @since 7.2.0
	 *
	 * @param array $item The current secret's metadata.
	 */
	public function column_name( $item ) {
		echo esc_html( $item['name'] );
	}

	/**
	 * Handles the fingerprint column output.
	 *
	 * @since 7.2.0
	 *
	 * @param array $item The current secret's metadata.
	 */
	public function column_fingerprint( $item ) {
		echo '<code>' . esc_html( $item['fingerprint'] ) . '</code>';
	}

	/**
	 * Handles the created column output.
	 *
	 * @since 7.2.0
	 *
	 * @param array $item The current secret's metadata.
	 */
	public function column_created( $item ) {
		echo empty( $item['created'] ) ? '&mdash;' : esc_html( date_i18n( __( 'F j, Y' ), $item['created'] ) );
	}

	/**
	 * Handles the updated column output.
	 *
	 * @since 7.2.0
	 *
	 * @param array $item The current secret's metadata.
	 */
	public function column_updated( $item ) {
		echo empty( $item['updated'] ) ? '&mdash;' : esc_html( date_i18n( __( 'F j, Y' ), $item['updated'] ) );
	}

	/**
	 * Handles the needs-rotation status column output.
	 *
	 * @since 7.2.0
	 *
	 * @param array $item The current secret's metadata.
	 */
	public function column_needs_rotation( $item ) {
		if ( ! empty( $item['needs_rotation'] ) ) {
			echo '<span class="dashicons dashicons-warning" aria-hidden="true"></span> ' . esc_html__( 'Needs rotation' );
		} else {
			echo esc_html__( 'OK' );
		}
	}

	/**
	 * Handles the delete column output.
	 *
	 * @since 7.2.0
	 *
	 * @param array $item The current secret's metadata.
	 */
	public function column_delete( $item ) {
		$url = wp_nonce_url(
			add_query_arg(
				array(
					'action' => $this->network ? 'delete_network_secret' : 'delete_secret',
					'name'   => rawurlencode( $item['name'] ),
				)
			),
			'wp-secrets-delete_' . $item['name']
		);

		printf(
			'<a href="%1$s" class="button delete" onclick="return confirm(%2$s);">%3$s</a>',
			esc_url( $url ),
			esc_attr(
				wp_json_encode(
					sprintf(
						/* translators: %s: the secret's name. */
						__( 'Delete the secret "%s"? This cannot be undone.' ),
						$item['name']
					)
				)
			),
			esc_html__( 'Delete' )
		);
	}

	/**
	 * Gets the name of the default primary column.
	 *
	 * @since 7.2.0
	 *
	 * @return string Name of the default primary column, in this case, 'name'.
	 */
	protected function get_default_primary_column_name() {
		return 'name';
	}

	/**
	 * Message to show when there are no items.
	 *
	 * @since 7.2.0
	 */
	public function no_items() {
		esc_html_e( 'No secrets found.' );
	}
}
