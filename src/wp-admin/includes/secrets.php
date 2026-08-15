<?php
/**
 * Secrets API: Administration screens.
 *
 * Modeled on core's existing patterns for special settings (the admin
 * email change screen, application passwords) rather than inventing a
 * new one: a list table of metadata, a form to add or overwrite, and a
 * confirmed delete. There is no reveal, no edit-in-place, and no copy
 * button anywhere on either screen.
 *
 * @package WordPress
 * @subpackage Administration
 */

/**
 * Registers the site-level Secrets admin screen.
 *
 * @since 7.2.0
 */
function wp_secrets_add_admin_menu() {
	$hook = add_options_page(
		__( 'Secrets' ),
		__( 'Secrets' ),
		'manage_secrets',
		'wp-secrets',
		'wp_secrets_render_admin_page'
	);

	add_action( "load-{$hook}", 'wp_secrets_handle_admin_actions' );
}
add_action( 'admin_menu', 'wp_secrets_add_admin_menu' );

/**
 * Registers the network-level Secrets admin screen.
 *
 * Separate from, and gated separately from, the site-level screen.
 *
 * @since 7.2.0
 */
function wp_secrets_add_network_admin_menu() {
	$hook = add_submenu_page(
		'settings.php',
		__( 'Secrets' ),
		__( 'Secrets' ),
		'manage_network_secrets',
		'wp-secrets-network',
		'wp_secrets_render_network_admin_page'
	);

	add_action( "load-{$hook}", 'wp_secrets_handle_network_admin_actions' );
}
add_action( 'network_admin_menu', 'wp_secrets_add_network_admin_menu' );

/**
 * Renders the site-level Secrets admin screen.
 *
 * @since 7.2.0
 */
function wp_secrets_render_admin_page() {
	wp_secrets_render_screen( false );
}

/**
 * Renders the network-level Secrets admin screen.
 *
 * @since 7.2.0
 */
function wp_secrets_render_network_admin_page() {
	wp_secrets_render_screen( true );
}

/**
 * Renders a Secrets admin screen.
 *
 * @since 7.2.0
 * @access private
 *
 * @param bool $network Whether this is the network-level screen.
 */
function wp_secrets_render_screen( $network ) {
	$capability = $network ? 'manage_network_secrets' : 'manage_secrets';

	if ( ! current_user_can( $capability ) ) {
		wp_die( __( 'Sorry, you are not allowed to manage secrets for this site.' ) );
	}

	$list_table = _get_list_table( 'WP_Secrets_List_Table', array( 'network' => $network ) );
	$list_table->prepare_items();

	$action_page = $network ? 'settings.php?page=wp-secrets-network' : 'options-general.php?page=wp-secrets';
	?>
	<div class="wrap">
		<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>

		<?php wp_secrets_render_admin_notices(); ?>

		<?php $list_table->display(); ?>

		<h2><?php esc_html_e( 'Add or overwrite a secret' ); ?></h2>
		<p>
			<?php esc_html_e( 'Overwriting an existing secret replaces its value. There is no way to view a stored value once it has been saved.' ); ?>
		</p>
		<form method="post" action="<?php echo esc_url( admin_url( $action_page ) ); ?>">
			<?php wp_nonce_field( 'wp-secrets-set' ); ?>
			<input type="hidden" name="wp_secrets_action" value="set" />
			<table class="form-table" role="presentation">
				<tr>
					<th scope="row"><label for="wp-secrets-name"><?php esc_html_e( 'Name' ); ?></label></th>
					<td>
						<input type="text" id="wp-secrets-name" name="name" class="regular-text" placeholder="plugin-slug/secret-name" required="required" />
					</td>
				</tr>
				<tr>
					<th scope="row"><label for="wp-secrets-value"><?php esc_html_e( 'Value' ); ?></label></th>
					<td>
						<input type="password" id="wp-secrets-value" name="value" class="regular-text" autocomplete="off" required="required" />
					</td>
				</tr>
			</table>
			<?php submit_button( __( 'Save Secret' ) ); ?>
		</form>
	</div>
	<?php
}

/**
 * Renders admin notices for the Secrets screens, based on the request's query args.
 *
 * @since 7.2.0
 * @access private
 */
function wp_secrets_render_admin_notices() {
	if ( isset( $_GET['wp_secrets_saved'] ) ) {
		if ( '1' === $_GET['wp_secrets_saved'] ) {
			wp_admin_notice( __( 'Secret saved.' ), array( 'type' => 'success' ) );
		} else {
			wp_admin_notice( __( 'The secret could not be saved.' ), array( 'type' => 'error' ) );
		}
	}

	if ( isset( $_GET['wp_secrets_deleted'] ) ) {
		if ( '1' === $_GET['wp_secrets_deleted'] ) {
			wp_admin_notice( __( 'Secret deleted.' ), array( 'type' => 'success' ) );
		} else {
			wp_admin_notice( __( 'The secret could not be deleted.' ), array( 'type' => 'error' ) );
		}
	}
}

/**
 * Handles add/overwrite and delete requests for the site-level Secrets screen.
 *
 * @since 7.2.0
 */
function wp_secrets_handle_admin_actions() {
	wp_secrets_handle_actions( false );
}

/**
 * Handles add/overwrite and delete requests for the network-level Secrets screen.
 *
 * @since 7.2.0
 */
function wp_secrets_handle_network_admin_actions() {
	wp_secrets_handle_actions( true );
}

/**
 * Handles add/overwrite and delete requests for a Secrets admin screen.
 *
 * @since 7.2.0
 * @access private
 *
 * @param bool $network Whether this is the network-level screen.
 */
function wp_secrets_handle_actions( $network ) {
	$capability = $network ? 'manage_network_secrets' : 'manage_secrets';

	if ( ! current_user_can( $capability ) ) {
		return;
	}

	$redirect_to = $network ? network_admin_url( 'settings.php?page=wp-secrets-network' ) : admin_url( 'options-general.php?page=wp-secrets' );

	$delete_action = $network ? 'delete_network_secret' : 'delete_secret';

	if ( isset( $_GET['action'], $_GET['name'] ) && $delete_action === $_GET['action'] ) {
		$name = sanitize_text_field( wp_unslash( $_GET['name'] ) );

		check_admin_referer( 'wp-secrets-delete_' . $name );

		$deleted = $network ? wp_delete_network_secret( $name ) : wp_delete_secret( $name );

		wp_safe_redirect( add_query_arg( 'wp_secrets_deleted', is_wp_error( $deleted ) ? '0' : '1', $redirect_to ) );
		exit;
	}

	if ( isset( $_POST['wp_secrets_action'] ) && 'set' === $_POST['wp_secrets_action'] ) {
		check_admin_referer( 'wp-secrets-set' );

		$name  = isset( $_POST['name'] ) ? sanitize_text_field( wp_unslash( $_POST['name'] ) ) : '';
		$value = isset( $_POST['value'] ) ? (string) wp_unslash( $_POST['value'] ) : '';

		$set = $network ? wp_set_network_secret( $name, $value ) : wp_set_secret( $name, $value );

		wp_secrets_memzero( $value );

		wp_safe_redirect( add_query_arg( 'wp_secrets_saved', is_wp_error( $set ) ? '0' : '1', $redirect_to ) );
		exit;
	}
}
