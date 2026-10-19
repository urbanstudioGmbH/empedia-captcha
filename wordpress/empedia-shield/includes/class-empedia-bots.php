<?php
/**
 * Bot protection ( tab “Bot protection” ). The protection itself is built into the plugin ( includes/captcha ) and works
 * with keys entered by hand. When the site is connected to EMPEDIAcloud, one click creates the keys for this domain.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Bots {

	public static function init() {
		add_action( 'admin_post_empedia_cloud_bots_enable', array( __CLASS__, 'handle_enable' ) );
	}

	private static function back( $type, $text ) {
		Empedia_Cloud_Admin::flash( $type, $text );
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'bots' ) );
		exit;
	}

	/** Is the built-in bot protection available ( not replaced by a still active separate plugin )? */
	private static function module() {
		return class_exists( 'Empedia_Captcha_Plugin' );
	}

	public static function handle_enable() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'empedia_cloud_bots_enable' );
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			self::back( 'error', __( 'Connect this site to EMPEDIAcloud first, or enter the keys by hand below.', 'empedia-shield' ) );
		}
		$data = Empedia_Cloud_Client::request( 'POST', '/captcha', new stdClass() );
		if ( is_wp_error( $data ) ) {
			if ( 'empedia_site_limit' === $data->get_error_code() ) {
				self::back( 'error', __( 'Your bot protection plan has no free domain left. Choose a bot protection plan in EMPEDIAcloud to protect more domains.', 'empedia-shield' ) );
			}
			self::back( 'error', $data->get_error_message() );
		}
		if ( empty( $data['sitekey'] ) || empty( $data['secret'] ) || empty( $data['base'] ) ) {
			self::back( 'error', __( 'EMPEDIAcloud returned an error. Please try again later.', 'empedia-shield' ) );
		}
		$o = get_option( 'empedia_captcha', array() );
		$o = is_array( $o ) ? $o : array();
		$o = array_merge(
			array( 'fail_open' => 1, 'content_check' => 0, 'gate' => 0, 'forms' => array( 'login' => 0, 'register' => 1, 'lostpassword' => 1, 'comment' => 1, 'cf7' => 1, 'woo' => 1 ) ),
			$o,
			array( 'base' => esc_url_raw( $data['base'] ), 'sitekey' => sanitize_text_field( $data['sitekey'] ), 'secret' => sanitize_text_field( $data['secret'] ) )
		);
		update_option( 'empedia_captcha', $o, false );
		self::back( 'success', __( 'Bot protection is active for your forms. The sign-in form is left out on purpose: try it in a second browser window first, then switch it on below.', 'empedia-shield' ) );
	}

	public static function render_tab() {
		if ( ! self::module() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The separate plugin “EMPEDIAcaptcha” is still active and runs the bot protection. Deactivate and delete it on the Plugins page – your keys and settings are kept and then managed here.', 'empedia-shield' ) . '</p></div>';
			return;
		}
		self::render_setup();
		// The form is always shown ( also without a connection, and when the cloud cannot be reached ).
		echo '<h2>' . esc_html__( 'Protected forms and options', 'empedia-shield' ) . '</h2>';
		Empedia_Captcha_Plugin::render_form();
	}

	/** Usage of the bot protection plan; the link to the plans only shows when the limit is near. */
	private static function render_quota( array $state ) {
		if ( empty( $state['quota'] ) || ! is_array( $state['quota'] ) || null === $state['quota']['checks'] ) {
			return;
		}
		$q    = $state['quota'];
		$used = (int) $q['checks_used'];
		$max  = max( 1, (int) $q['checks'] );
		printf(
			'<p>%s</p><progress value="%d" max="%d" style="width:100%%;max-width:420px"></progress>',
			esc_html( sprintf( /* translators: 1: checks used this month, 2: checks included */ __( '%1$s of %2$s checks used this month', 'empedia-shield' ), number_format_i18n( $used ), number_format_i18n( $max ) ) ),
			absint( min( $used, $max ) ),
			absint( $max )
		);
		if ( ! empty( $q['near'] ) && ! empty( $state['plans_url'] ) ) {
			$text = ! empty( $q['reached'] ) && ! empty( $q['hard_limit'] )
				? __( 'The included checks are used up. Until the next month, forms are no longer protected. Choose a larger plan to continue right away.', 'empedia-shield' )
				: __( 'You are close to the included checks. Choose a larger plan so protection does not stop.', 'empedia-shield' );
			echo '<div class="notice notice-warning inline"><p>' . esc_html( $text ) . '</p></div>';
			printf( '<p><a class="button" href="%s" target="_blank" rel="noopener noreferrer">%s</a></p>', esc_url( $state['plans_url'] ), esc_html__( 'Choose a bot protection plan', 'empedia-shield' ) );
		}
	}

	private static function render_setup() {
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Protect forms from bots', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'EMPEDIAcaptcha protects the sign-in, registration, password reset, comment and shop forms without cookies and without puzzles for your visitors. It needs a site key and a secret key of the EMPEDIAcaptcha service: enter them below, or let this page create them for you when the site is connected to EMPEDIAcloud.', 'empedia-shield' ) . '</p>';
		$opts = get_option( 'empedia_captcha', array() );
		$set  = is_array( $opts ) && ! empty( $opts['sitekey'] ) && ! empty( $opts['secret'] );
		if ( ! Empedia_Cloud_Client::is_connected() ) {
			echo '<p>' . esc_html__( 'Not connected to EMPEDIAcloud: enter the keys by hand below, or connect first to have them set up for you.', 'empedia-shield' ) . '</p>';
			printf( '<p><a class="button" href="%s">%s</a></p></div>', esc_url( Empedia_Cloud_Admin::tab_url( 'overview' ) ), esc_html__( 'Go to the connection', 'empedia-shield' ) );
			return;
		}
		$state = Empedia_Cloud_Client::request( 'GET', '/captcha' );
		if ( is_wp_error( $state ) ) {
			echo '<div class="notice notice-error inline"><p>' . esc_html( $state->get_error_message() ) . '</p></div></div>';
			return;
		}
		if ( empty( $state['available'] ) ) {
			echo '<p>' . esc_html__( 'Automatic setup is not available for your account yet. You can enter the keys by hand below.', 'empedia-shield' ) . '</p></div>';
			return;
		}
		self::render_quota( $state );
		echo '<p>';
		if ( $set && ! empty( $state['connected'] ) ) {
			echo '<span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> ' . esc_html__( 'Active for this site.', 'empedia-shield' );
		} else {
			echo '<span class="dashicons dashicons-warning" style="color:#dba617"></span> ' . esc_html__( 'Not active yet.', 'empedia-shield' );
		}
		echo '</p><form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_bots_enable">';
		wp_nonce_field( 'empedia_cloud_bots_enable' );
		$label = $set ? __( 'Renew the keys', 'empedia-shield' ) : __( 'Activate bot protection', 'empedia-shield' );
		echo '<button type="submit" class="button button-primary">' . esc_html( $label ) . '</button></form>';
		echo '</div>';
	}
}
