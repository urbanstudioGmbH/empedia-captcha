<?php
/**
 * Administration for the sign-in protection: second factor on the profile page, settings tab "Sign-in protection".
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Protect_Admin {

	public static function init() {
		add_action( 'show_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'edit_user_profile', array( __CLASS__, 'profile_section' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'profile_assets' ) );
		add_action( 'admin_notices', array( __CLASS__, 'profile_notice' ) );
		add_action( 'admin_footer', array( __CLASS__, 'print_forms' ) );
		foreach ( array( 'totp_start', 'totp_confirm', 'totp_disable', 'recovery_regen', 'pk_delete', 'tfa_reset', 'protect_save' ) as $a ) {
			add_action( 'admin_post_empedia_cloud_' . $a, array( __CLASS__, 'handle_' . $a ) );
		}
		add_action( 'wp_ajax_empedia_cloud_pk_register', array( __CLASS__, 'ajax_pk_register' ) );
	}

	/* ------------------------------------------------------------------ helpers */

	private static function target_user() {
		$uid = isset( $_REQUEST['user_id'] ) ? (int) $_REQUEST['user_id'] : get_current_user_id(); // phpcs:ignore WordPress.Security.NonceVerification
		if ( $uid !== get_current_user_id() && ! current_user_can( 'edit_user', $uid ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		$u = get_userdata( $uid );
		if ( ! $u ) {
			wp_die( esc_html__( 'User not found.', 'empedia-shield' ), '', array( 'response' => 404 ) );
		}
		return $u;
	}

	private static function back( $u, $flag = '' ) {
		$url = $u->ID === get_current_user_id() ? admin_url( 'profile.php' ) : admin_url( 'user-edit.php?user_id=' . $u->ID );
		if ( $flag ) {
			$url = add_query_arg( 'empedia_msg', $flag, $url );
		}
		wp_safe_redirect( $url . '#empedia-2fa' );
		exit;
	}

	/** Forms registered while the profile section is rendered; printed in the footer ( a <form> cannot be nested ). */
	private static $forms = array();

	/** Registers a form and returns its id; inputs and buttons join it with the attribute form="…". */
	private static function form_id( $action, $u, $extra = '' ) {
		$id = 'empedia-f-' . $action . '-' . count( self::$forms );
		ob_start();
		echo '<input type="hidden" name="action" value="empedia_cloud_' . esc_attr( $action ) . '"><input type="hidden" name="user_id" value="' . (int) $u->ID . '">';
		echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce( 'empedia_cloud_' . $action . '_' . $u->ID ) ) . '">';
		echo $extra; // phpcs:ignore WordPress.Security.EscapeOutput -- built from escaped parts by the callers
		self::$forms[ $id ] = ob_get_clean();
		return $id;
	}

	private static function form( $action, $u, $label, $class = 'button', $extra = '' ) {
		$id = self::form_id( $action, $u, $extra );
		echo '<button type="submit" form="' . esc_attr( $id ) . '" class="' . esc_attr( $class ) . '" style="margin:0 8px 8px 0">' . esc_html( $label ) . '</button>';
	}

	public static function print_forms() {
		foreach ( self::$forms as $id => $fields ) {
			echo '<form id="' . esc_attr( $id ) . '" method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '">' . $fields . '</form>'; // phpcs:ignore WordPress.Security.EscapeOutput
		}
		self::$forms = array();
	}

	/* ------------------------------------------------------------------ profile */

	public static function profile_assets( $hook ) {
		if ( ! in_array( $hook, array( 'profile.php', 'user-edit.php' ), true ) || Empedia_Cloud_Protect::off() ) {
			return;
		}
		wp_enqueue_script( 'empedia-cloud-qr', EMPEDIA_CLOUD_URL_BASE . 'assets/qrcode.js', array(), '1.4.4', true );
		wp_enqueue_script( 'empedia-cloud-profile', EMPEDIA_CLOUD_URL_BASE . 'assets/profile.js', array( 'empedia-cloud-qr' ), EMPEDIA_CLOUD_VERSION, true );
		wp_enqueue_script( 'empedia-cloud-passkey', EMPEDIA_CLOUD_URL_BASE . 'assets/passkey.js', array(), EMPEDIA_CLOUD_VERSION, true );
		wp_localize_script(
			'empedia-cloud-passkey',
			'EmpediaPasskey',
			array(
				'ajax'  => admin_url( 'admin-ajax.php' ),
				'nonce' => wp_create_nonce( 'empedia_cloud_passkey' ),
				'i18n'  => array(
					'failed'      => __( 'The passkey could not be set up. Please try again.', 'empedia-shield' ),
					'unsupported' => __( 'This browser does not support passkeys.', 'empedia-shield' ),
					'codes'       => __( 'Your recovery codes. Each works once if you lose this device. Store them safely; they are not shown again:', 'empedia-shield' ),
				),
			)
		);
	}

	public static function profile_notice() {
		global $pagenow;
		if ( ! Empedia_Cloud_Protect::off() && is_user_logged_in() && Empedia_Cloud_Protect::totp_broken( get_current_user_id() ) && 'profile.php' !== $pagenow ) {
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Your authenticator app can no longer be read (the security keys of this site were changed). Please set it up again.', 'empedia-shield' ) . ' <a href="' . esc_url( admin_url( 'profile.php#empedia-2fa' ) ) . '">' . esc_html__( 'Open profile', 'empedia-shield' ) . '</a></p></div>';
		}
		if ( ! in_array( $pagenow, array( 'profile.php', 'user-edit.php' ), true ) || Empedia_Cloud_Protect::off() ) {
			return;
		}
		// phpcs:disable WordPress.Security.NonceVerification
		if ( isset( $_GET['empedia_2fa'] ) && 'required' === $_GET['empedia_2fa'] ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
			echo '<div class="notice notice-warning"><p>' . esc_html__( 'Your role requires two-factor authentication. Please set up an authenticator app or a passkey below to continue.', 'empedia-shield' ) . '</p></div>';
		}
		$msgs = array(
			'totp_on'   => array( 'success', __( 'The authenticator app is now active.', 'empedia-shield' ) ),
			'totp_bad'  => array( 'error', __( 'The code was not correct. Please try again.', 'empedia-shield' ) ),
			'totp_off'  => array( 'success', __( 'The authenticator app was removed.', 'empedia-shield' ) ),
			'pw_bad'    => array( 'error', __( 'The password was not correct.', 'empedia-shield' ) ),
			'pk_gone'   => array( 'success', __( 'The passkey was removed.', 'empedia-shield' ) ),
			'reset'     => array( 'success', __( 'The second factor of this user was reset.', 'empedia-shield' ) ),
			'totp_exists' => array( 'error', __( 'An authenticator app is already set up. Remove it first to set up a new one.', 'empedia-shield' ) ),
			'codes_new'   => array( 'success', __( 'New recovery codes were created.', 'empedia-shield' ) ),
		);
		$mk = isset( $_GET['empedia_msg'] ) && is_string( $_GET['empedia_msg'] ) ? sanitize_key( wp_unslash( $_GET['empedia_msg'] ) ) : '';
		if ( '' !== $mk && isset( $msgs[ $mk ] ) ) {
			$m = $msgs[ $mk ];
			echo '<div class="notice notice-' . esc_attr( $m[0] ) . ' is-dismissible"><p>' . esc_html( $m[1] ) . '</p></div>';
		}
		// phpcs:enable
	}

	public static function profile_section( $user ) {
		if ( Empedia_Cloud_Protect::off() || Empedia_Cloud_Protect::tfa_off() ) {
			return;
		}
		$s    = Empedia_Cloud_Protect::settings();
		$own  = get_current_user_id() === $user->ID;
		$totp = $s['tfa_totp'] && Empedia_Cloud_Totp::supported();
		$pk   = $s['tfa_passkeys'] && Empedia_Cloud_Webauthn::usable();
		if ( ! $totp && ! $pk && ! Empedia_Cloud_Protect::has_totp( $user->ID ) && ! Empedia_Cloud_Protect::has_passkeys( $user->ID ) ) {
			return;
		}
		echo '<h2 id="empedia-2fa">' . esc_html__( 'Two-factor authentication (EMPEDIAcloud)', 'empedia-shield' ) . '</h2>';
		echo '<table class="form-table" role="presentation">';

		// Authenticator app.
		echo '<tr><th>' . esc_html__( 'Authenticator app', 'empedia-shield' ) . '</th><td>';
		$has_totp = Empedia_Cloud_Protect::has_totp( $user->ID );
		if ( $has_totp ) {
			echo '<p><span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> ' . esc_html__( 'Active.', 'empedia-shield' ) . '</p>';
			if ( $own ) {
				$fid = self::form_id( 'totp_disable', $user );
				echo '<p><label>' . esc_html__( 'Current password', 'empedia-shield' ) . ' <input type="password" form="' . esc_attr( $fid ) . '" name="empedia_pw" autocomplete="current-password" required></label> ';
				echo '<button type="submit" form="' . esc_attr( $fid ) . '" class="button">' . esc_html__( 'Remove authenticator app', 'empedia-shield' ) . '</button></p>';
			}
		} elseif ( $own && $totp ) {
			if ( Empedia_Cloud_Protect::totp_broken( $user->ID ) ) {
				echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Your authenticator app can no longer be read (the security keys of this site were changed). Please set it up again.', 'empedia-shield' ) . '</p></div>';
			}
			$pending = Empedia_Cloud_Totp::unseal( get_user_meta( $user->ID, 'empedia_totp_pending', true ) );
			if ( '' === $pending ) {
				echo '<p>' . esc_html__( 'Use an app such as Aegis, 2FAS, Google Authenticator or Microsoft Authenticator to create sign-in codes.', 'empedia-shield' ) . '</p>';
				$fid = self::form_id( 'totp_start', $user );
				echo '<p><label>' . esc_html__( 'Current password', 'empedia-shield' ) . ' <input type="password" form="' . esc_attr( $fid ) . '" name="empedia_pw" autocomplete="current-password" required></label> ';
				echo '<button type="submit" form="' . esc_attr( $fid ) . '" class="button button-primary">' . esc_html__( 'Set up authenticator app', 'empedia-shield' ) . '</button></p>';
			} else {
				$uri = Empedia_Cloud_Totp::uri( $pending, $user->user_login, wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) );
				echo '<p>' . esc_html__( 'Scan the code with your app, or enter the key by hand. Then type the 6-digit code to finish.', 'empedia-shield' ) . '</p>';
				echo '<p><img id="empedia-totp-qr" data-uri="' . esc_attr( $uri ) . '" alt="" width="200" height="200" style="display:none;background:#fff;padding:8px;border:1px solid #c3c4c7"></p>';
				echo '<p><code style="font-size:14px;letter-spacing:1px">' . esc_html( trim( chunk_split( $pending, 4, ' ' ) ) ) . '</code></p>';
				$fid = self::form_id( 'totp_confirm', $user );
				echo '<p><input type="text" form="' . esc_attr( $fid ) . '" name="empedia_code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" size="10" required> <button type="submit" form="' . esc_attr( $fid ) . '" class="button button-primary">' . esc_html__( 'Activate', 'empedia-shield' ) . '</button></p>';
			}
		} else {
			echo '<p>' . esc_html__( 'Not set up.', 'empedia-shield' ) . '</p>';
		}
		echo '</td></tr>';

		// Passkeys.
		echo '<tr><th>' . esc_html__( 'Passkeys', 'empedia-shield' ) . '</th><td>';
		$creds = Empedia_Cloud_Webauthn::credentials( $user->ID );
		if ( $creds ) {
			echo '<ul style="margin-top:0">';
			foreach ( $creds as $c ) {
				echo '<li>' . esc_html( $c['name'] ) . ' <span class="description">(' . esc_html(
					$c['used']
						/* translators: %s: date */
						? sprintf( __( 'last used %s', 'empedia-shield' ), Empedia_Cloud_Admin::fmt_date( (int) $c['used'], false ) )
						/* translators: %s: date */
						: sprintf( __( 'added %s', 'empedia-shield' ), Empedia_Cloud_Admin::fmt_date( (int) $c['created'], false ) )
				) . ')</span> ';
				$fid = self::form_id( 'pk_delete', $user, '<input type="hidden" name="cred" value="' . esc_attr( $c['id'] ) . '">' );
				echo '<input type="password" form="' . esc_attr( $fid ) . '" name="empedia_pw" autocomplete="current-password" placeholder="' . esc_attr__( 'Current password', 'empedia-shield' ) . '" required style="width:150px"> ';
				echo '<button type="submit" form="' . esc_attr( $fid ) . '" class="button-link button-link-delete">' . esc_html__( 'Remove', 'empedia-shield' ) . '</button>';
				echo '</li>';
			}
			echo '</ul>';
		} else {
			echo '<p>' . esc_html__( 'No passkey set up.', 'empedia-shield' ) . '</p>';
		}
		if ( $own && $pk ) {
			echo '<p><input type="text" id="empedia-pk-name" placeholder="' . esc_attr__( 'Name (optional)', 'empedia-shield' ) . '" maxlength="60" autocomplete="off" data-lpignore="true" data-1p-ignore> <button type="button" class="button" id="empedia-pk-add">' . esc_html__( 'Add a passkey', 'empedia-shield' ) . '</button></p>';
			echo '<p class="description">' . esc_html__( 'A passkey uses your device unlock (fingerprint, face or PIN). It only works on this website address.', 'empedia-shield' ) . '</p>';
		} elseif ( $own && ! $pk && $s['tfa_passkeys'] ) {
			echo '<p class="description">' . esc_html__( 'Passkeys need a secure connection (https).', 'empedia-shield' ) . '</p>';
		}
		echo '</td></tr>';

		// Recovery codes / reset.
		if ( ( $has_totp || $creds ) && $own ) {
			$left = get_user_meta( $user->ID, 'empedia_recovery', true );
			echo '<tr><th>' . esc_html__( 'Recovery codes', 'empedia-shield' ) . '</th><td>';
			/* translators: %d: number of unused codes */
			echo '<p>' . esc_html( sprintf( __( 'Unused codes: %d. Each code works once if you lose your device.', 'empedia-shield' ), is_array( $left ) ? count( $left ) : 0 ) ) . '</p>';
			$fid = self::form_id( 'recovery_regen', $user );
			echo '<p><label>' . esc_html__( 'Current password', 'empedia-shield' ) . ' <input type="password" form="' . esc_attr( $fid ) . '" name="empedia_pw" autocomplete="current-password" required></label> ';
			echo '<button type="submit" form="' . esc_attr( $fid ) . '" class="button">' . esc_html__( 'Create new recovery codes', 'empedia-shield' ) . '</button></p>';
			echo '</td></tr>';
		}
		if ( ! $own && current_user_can( 'edit_user', $user->ID ) && ( $has_totp || $creds ) ) {
			echo '<tr><th>' . esc_html__( 'Reset', 'empedia-shield' ) . '</th><td>';
			$fid = self::form_id( 'tfa_reset', $user );
			echo '<p><label>' . esc_html__( 'Your password', 'empedia-shield' ) . ' <input type="password" form="' . esc_attr( $fid ) . '" name="empedia_pw" autocomplete="current-password" required></label> ';
			echo '<button type="submit" form="' . esc_attr( $fid ) . '" class="button button-link-delete">' . esc_html__( 'Remove all second factors of this user', 'empedia-shield' ) . '</button></p>';
			echo '<p class="description">' . esc_html__( 'Use this if the user lost the device and the recovery codes.', 'empedia-shield' ) . '</p></td></tr>';
		}
		echo '</table>';
	}

	/* ------------------------------------------------------------------ profile actions */

	public static function handle_totp_start() {
		$u = self::target_user();
		check_admin_referer( 'empedia_cloud_totp_start_' . $u->ID );
		if ( $u->ID !== get_current_user_id() || ! Empedia_Cloud_Totp::supported() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		if ( Empedia_Cloud_Protect::has_totp( $u->ID ) ) {
			self::back( $u, 'totp_exists' );
		}
		$pw = isset( $_POST['empedia_pw'] ) ? wp_unslash( $_POST['empedia_pw'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( ! self::password_ok( $u, $pw ) ) {
			self::back( $u, 'pw_bad' );
		}
		update_user_meta( $u->ID, 'empedia_totp_pending', Empedia_Cloud_Totp::seal( Empedia_Cloud_Totp::new_secret() ) );
		self::back( $u );
	}

	public static function handle_totp_confirm() {
		$u = self::target_user();
		check_admin_referer( 'empedia_cloud_totp_confirm_' . $u->ID );
		if ( $u->ID !== get_current_user_id() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		if ( Empedia_Cloud_Protect::has_totp( $u->ID ) ) {
			self::back( $u, 'totp_exists' );
		}
		$secret = Empedia_Cloud_Totp::unseal( get_user_meta( $u->ID, 'empedia_totp_pending', true ) );
		$code   = isset( $_POST['empedia_code'] ) ? sanitize_text_field( wp_unslash( $_POST['empedia_code'] ) ) : '';
		$ctr    = '' === $secret ? false : Empedia_Cloud_Totp::verify( $secret, $code );
		if ( false === $ctr ) {
			self::back( $u, 'totp_bad' );
		}
		update_user_meta( $u->ID, 'empedia_totp', Empedia_Cloud_Totp::seal( $secret ) );
		update_user_meta( $u->ID, 'empedia_totp_last', $ctr );
		delete_user_meta( $u->ID, 'empedia_totp_pending' );
		list( $plain, $hashes ) = Empedia_Cloud_Totp::new_recovery_codes();
		update_user_meta( $u->ID, 'empedia_recovery', $hashes );
		self::show_codes( $u, $plain );
	}

	public static function handle_recovery_regen() {
		$u = self::target_user();
		check_admin_referer( 'empedia_cloud_recovery_regen_' . $u->ID );
		if ( $u->ID !== get_current_user_id() || ! Empedia_Cloud_Protect::has_totp( $u->ID ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		$pw = isset( $_POST['empedia_pw'] ) ? wp_unslash( $_POST['empedia_pw'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( ! self::password_ok( $u, $pw ) ) {
			self::back( $u, 'pw_bad' );
		}
		list( $plain, $hashes ) = Empedia_Cloud_Totp::new_recovery_codes();
		update_user_meta( $u->ID, 'empedia_recovery', $hashes );
		self::show_codes( $u, $plain );
	}

	/** Password check for sensitive changes, limited to a few attempts. */
	private static function password_ok( $u, $pw ) {
		if ( Empedia_Cloud_Atomic::hit( 'pwcheck:' . $u->ID, 10 * MINUTE_IN_SECONDS ) > 10 ) {
			return false;
		}
		return is_string( $pw ) && '' !== $pw && wp_check_password( $pw, $u->user_pass, $u->ID );
	}

	/** Shown once, directly in the response ( never stored in readable form ). */
	private static function show_codes( $u, $codes ) {
		$html  = '<h1>' . esc_html__( 'Your recovery codes', 'empedia-shield' ) . '</h1>';
		$html .= '<p>' . esc_html__( 'Store these codes safely. Each one works once if you cannot use your authenticator app. They are not shown again.', 'empedia-shield' ) . '</p>';
		$html .= '<pre style="font-size:16px;line-height:1.8">' . esc_html( implode( "\n", $codes ) ) . '</pre>';
		$html .= '<p><a class="button button-primary" href="' . esc_url( admin_url( 'profile.php?empedia_msg=totp_on#empedia-2fa' ) ) . '">' . esc_html__( 'I have saved them', 'empedia-shield' ) . '</a></p>';
		wp_die( $html, esc_html__( 'Recovery codes', 'empedia-shield' ), array( 'response' => 200 ) ); // phpcs:ignore WordPress.Security.EscapeOutput
	}

	public static function handle_totp_disable() {
		$u = self::target_user();
		check_admin_referer( 'empedia_cloud_totp_disable_' . $u->ID );
		if ( $u->ID !== get_current_user_id() ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		$pw = isset( $_POST['empedia_pw'] ) ? wp_unslash( $_POST['empedia_pw'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( ! self::password_ok( $u, $pw ) ) {
			self::back( $u, 'pw_bad' );
		}
		foreach ( array( 'empedia_totp', 'empedia_totp_pending', 'empedia_totp_last', 'empedia_recovery' ) as $m ) {
			delete_user_meta( $u->ID, $m );
		}
		self::back( $u, 'totp_off' );
	}

	public static function handle_pk_delete() {
		$u  = self::target_user();
		check_admin_referer( 'empedia_cloud_pk_delete_' . $u->ID );
		$me = wp_get_current_user();
		$pw = isset( $_POST['empedia_pw'] ) ? wp_unslash( $_POST['empedia_pw'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( ! self::password_ok( $me, $pw ) ) {
			self::back( $u, 'pw_bad' );
		}
		$id = isset( $_POST['cred'] ) ? sanitize_text_field( wp_unslash( $_POST['cred'] ) ) : '';
		Empedia_Cloud_Webauthn::remove_credential( $u->ID, $id );
		self::back( $u, 'pk_gone' );
	}

	public static function handle_tfa_reset() {
		$u = self::target_user();
		check_admin_referer( 'empedia_cloud_tfa_reset_' . $u->ID );
		if ( $u->ID === get_current_user_id() || ! current_user_can( 'edit_user', $u->ID ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		$pw = isset( $_POST['empedia_pw'] ) ? wp_unslash( $_POST['empedia_pw'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( ! self::password_ok( wp_get_current_user(), $pw ) ) {
			self::back( $u, 'pw_bad' );
		}
		Empedia_Cloud_Protect::forget_user( $u->ID );
		self::back( $u, 'reset' );
	}

	public static function ajax_pk_register() {
		if ( ! is_user_logged_in() || ! check_ajax_referer( 'empedia_cloud_passkey', 'nonce', false ) || ! Empedia_Cloud_Webauthn::usable() || Empedia_Cloud_Protect::tfa_off() ) {
			wp_send_json_error( array(), 403 );
		}
		$u    = wp_get_current_user();
		$resp = array(
			'id'                => isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '',
			'clientDataJSON'    => isset( $_POST['clientDataJSON'] ) ? sanitize_text_field( wp_unslash( $_POST['clientDataJSON'] ) ) : '',
			'attestationObject' => isset( $_POST['attestationObject'] ) ? sanitize_text_field( wp_unslash( $_POST['attestationObject'] ) ) : '',
		);
		$attach = isset( $_POST['attachment'] ) && 'platform' === sanitize_key( wp_unslash( $_POST['attachment'] ) ) ? 'platform' : '';
		$cred = Empedia_Cloud_Webauthn::registration_finish( $u, isset( $_POST['ticket'] ) ? sanitize_text_field( wp_unslash( $_POST['ticket'] ) ) : '', $resp, isset( $_POST['name'] ) ? wp_unslash( $_POST['name'] ) : '', $attach ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( is_wp_error( $cred ) ) {
			wp_send_json_error( array( 'message' => $cred->get_error_message() ), 400 );
		}
		Empedia_Cloud_Webauthn::add_credential( $u->ID, $cred );
		self::notify_passkey( $u, $cred );
		// A passkey alone has no way back when the device is lost: the first one comes with recovery codes.
		$codes = array();
		if ( 0 === Empedia_Cloud_Protect::recovery_left( $u->ID ) ) {
			list( $codes, $hashes ) = Empedia_Cloud_Totp::new_recovery_codes();
			update_user_meta( $u->ID, 'empedia_recovery', $hashes );
		}
		wp_send_json_success( array( 'codes' => $codes ) );
	}

	/** Tells the owner by e-mail that a passkey was added ( a stolen session cannot do this unnoticed ). */
	private static function notify_passkey( $u, $cred ) {
		if ( ! $u->user_email ) {
			return;
		}
		$site = wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES );
		/* translators: %s: site name */
		$subject = sprintf( __( '[%s] A passkey was added to your account', 'empedia-shield' ), $site );
		/* translators: 1: passkey name, 2: site address */
		$body  = sprintf( __( 'A passkey (%1$s) was added to your account on %2$s.', 'empedia-shield' ), $cred['name'], home_url( '/' ) ) . "\n\n";
		$body .= __( 'If this was you, nothing to do. If not, sign in, remove the passkey in your profile and change your password.', 'empedia-shield' );
		wp_mail( $u->user_email, $subject, $body );
	}

	/* ------------------------------------------------------------------ settings tab */

	public static function handle_protect_save() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'empedia_cloud_protect_save' );
		$p   = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$o   = array(
			'limit_on'      => ! empty( $p['limit_on'] ),
			'limit_user'    => isset( $p['limit_user'] ) ? (int) $p['limit_user'] : 5,
			'limit_ip'      => isset( $p['limit_ip'] ) ? (int) $p['limit_ip'] : 15,
			'window'        => isset( $p['window'] ) ? (int) $p['window'] : 15,
			'lock_minutes'  => isset( $p['lock_minutes'] ) ? (int) $p['lock_minutes'] : 10,
			'allowlist'     => isset( $p['allowlist'] ) ? implode( "\n", array_filter( array_map( function ( $x ) {
				return filter_var( trim( $x ), FILTER_VALIDATE_IP ) ? trim( $x ) : '';
			}, preg_split( '/[\s,;]+/', (string) $p['allowlist'] ) ) ) ) : '',
			'tfa_totp'      => ! empty( $p['tfa_totp'] ),
			'tfa_passkeys'  => ! empty( $p['tfa_passkeys'] ),
			'passkey_login' => ! empty( $p['passkey_login'] ),
			'ip_source'     => isset( $p['ip_source'] ) && in_array( $p['ip_source'], array( 'remote', 'xff', 'cf', 'real' ), true ) ? $p['ip_source'] : 'remote',
			'enforce_roles' => isset( $p['enforce_roles'] ) && is_array( $p['enforce_roles'] ) ? array_values( array_intersect( array_map( 'sanitize_key', $p['enforce_roles'] ), array_keys( wp_roles()->roles ) ) ) : array(),
		);
		update_option( Empedia_Cloud_Protect::OPTION, $o, false );
		Empedia_Cloud_Admin::flash( 'success', __( 'Settings saved.', 'empedia-shield' ) );
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'login' ) );
		exit;
	}

	public static function render_tab() {
		$s  = Empedia_Cloud_Protect::settings();
		$st = Empedia_Cloud_Protect::stats();
		if ( Empedia_Cloud_Protect::off() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The sign-in protection is switched off by EMPEDIA_CLOUD_PROTECT_OFF in wp-config.php.', 'empedia-shield' ) . '</p></div>';
		}
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_protect_save">';
		wp_nonce_field( 'empedia_cloud_protect_save' );

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Failed sign-in attempts', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Blocks an address for a while after too many failed attempts. Every repeated block lasts twice as long. Addresses are never stored in readable form.', 'empedia-shield' ) . '</p>';
		/* translators: 1: failed attempts, 2: blocks */
		echo '<p class="description">' . esc_html( sprintf( __( 'Last 24–48 hours: %1$d failed attempts, %2$d blocks.', 'empedia-shield' ), $st['fail'], $st['lock'] ) ) . '</p>';
		echo '<table class="form-table" role="presentation">';
		echo '<tr><th>' . esc_html__( 'Protection', 'empedia-shield' ) . '</th><td><label><input type="checkbox" name="limit_on" value="1"' . checked( $s['limit_on'], true, false ) . '> ' . esc_html__( 'Block after too many failed attempts', 'empedia-shield' ) . '</label></td></tr>';
		echo '<tr><th>' . esc_html__( 'Attempts per user name', 'empedia-shield' ) . '</th><td><input type="number" name="limit_user" min="3" max="20" value="' . (int) $s['limit_user'] . '" class="small-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'Attempts per address', 'empedia-shield' ) . '</th><td><input type="number" name="limit_ip" min="5" max="100" value="' . (int) $s['limit_ip'] . '" class="small-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'Counting period (minutes)', 'empedia-shield' ) . '</th><td><input type="number" name="window" min="5" max="120" value="' . (int) $s['window'] . '" class="small-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'First block (minutes)', 'empedia-shield' ) . '</th><td><input type="number" name="lock_minutes" min="1" max="240" value="' . (int) $s['lock_minutes'] . '" class="small-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'Never block these addresses', 'empedia-shield' ) . '</th><td><textarea name="allowlist" rows="3" cols="40" class="code">' . esc_textarea( $s['allowlist'] ) . '</textarea><p class="description">' . esc_html__( 'One IP address per line, for example your office.', 'empedia-shield' ) . '</p>';
		echo '</td></tr>';
		echo '<tr><th>' . esc_html__( 'Visitor address', 'empedia-shield' ) . '</th><td><select name="ip_source">';
		foreach ( array(
			'remote' => __( 'Connection address (default)', 'empedia-shield' ),
			'xff'    => __( 'Header X-Forwarded-For (last entry)', 'empedia-shield' ),
			'cf'     => __( 'Header CF-Connecting-IP (Cloudflare)', 'empedia-shield' ),
			'real'   => __( 'Header X-Real-IP', 'empedia-shield' ),
		) as $k => $label ) {
			echo '<option value="' . esc_attr( $k ) . '"' . selected( $s['ip_source'], $k, false ) . '>' . esc_html( $label ) . '</option>';
		}
		echo '</select><p class="description">' . esc_html__( 'Only choose a header if your server or CDN sets it; a header that visitors can set themselves would let them avoid the blocks.', 'empedia-shield' ) . '</p>';
		if ( Empedia_Cloud_Protect::proxy_suspected() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Your visitors seem to come through a proxy or CDN: every visitor has the same connection address. Choose the matching header above, otherwise one blocked visitor blocks everyone.', 'empedia-shield' ) . '</p></div>';
		}
		echo '</td></tr>';
		echo '</table></div>';

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Two-factor authentication and passkeys', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Users set up their second factor on their own profile page. With a passkey, signing in needs no password.', 'empedia-shield' ) . '</p>';
		echo '<table class="form-table" role="presentation">';
		echo '<tr><th>' . esc_html__( 'Authenticator app', 'empedia-shield' ) . '</th><td><label><input type="checkbox" name="tfa_totp" value="1"' . checked( $s['tfa_totp'], true, false ) . disabled( Empedia_Cloud_Totp::supported(), false, false ) . '> ' . esc_html__( 'Allow (with recovery codes)', 'empedia-shield' ) . '</label></td></tr>';
		echo '<tr><th>' . esc_html__( 'Passkeys', 'empedia-shield' ) . '</th><td><label><input type="checkbox" name="tfa_passkeys" value="1"' . checked( $s['tfa_passkeys'], true, false ) . disabled( Empedia_Cloud_Webauthn::usable(), false, false ) . '> ' . esc_html__( 'Allow as second factor', 'empedia-shield' ) . '</label><br>';
		echo '<label><input type="checkbox" name="passkey_login" value="1"' . checked( $s['passkey_login'], true, false ) . disabled( Empedia_Cloud_Webauthn::usable(), false, false ) . '> ' . esc_html__( 'Show “Sign in with a passkey” on the sign-in page', 'empedia-shield' ) . '</label>';
		if ( ! Empedia_Cloud_Webauthn::usable() ) {
			echo '<p class="description">' . esc_html__( 'Passkeys need a secure connection (https) and the PHP extension OpenSSL.', 'empedia-shield' ) . '</p>';
		}
		echo '<p class="description">' . esc_html__( 'Passkeys are bound to this website address. If the address changes, they must be created again.', 'empedia-shield' ) . '</p></td></tr>';
		echo '<tr><th>' . esc_html__( 'Require for roles', 'empedia-shield' ) . '</th><td>';
		foreach ( wp_roles()->roles as $slug => $role ) {
			echo '<label style="display:block"><input type="checkbox" name="enforce_roles[]" value="' . esc_attr( $slug ) . '"' . checked( in_array( $slug, $s['enforce_roles'], true ), true, false ) . '> ' . esc_html( translate_user_role( $role['name'] ) ) . '</label>';
		}
		echo '<p class="description">' . esc_html__( 'Users of these roles are sent to their profile page until they have set up a second factor.', 'empedia-shield' ) . '</p></td></tr>';
		echo '</table></div>';
		echo '<p><button type="submit" class="button button-primary">' . esc_html__( 'Save settings', 'empedia-shield' ) . '</button></p></form>';

		Empedia_Cloud_Sso::render_card();

		echo '<div class="empedia-card"><h2>' . esc_html__( 'If you are locked out', 'empedia-shield' ) . '</h2><p>' . esc_html__( 'Add one of these lines to wp-config.php via FTP or your hosting panel, sign in, and remove it again:', 'empedia-shield' ) . '</p>';
		echo '<p><code>define( \'EMPEDIA_CLOUD_2FA_OFF\', true );</code> – ' . esc_html__( 'switches the second factor step off', 'empedia-shield' ) . '<br><code>define( \'EMPEDIA_CLOUD_PROTECT_OFF\', true );</code> – ' . esc_html__( 'switches the whole sign-in protection off', 'empedia-shield' ) . '</p></div>';
	}
}
