<?php
/**
 * Comments: switch them off ( everywhere, for chosen content types, for old content ), clean up ( delete by status and age )
 * and check existing comments with the content check of EMPEDIAcaptcha.
 *
 * Switching off only filters what WordPress shows and accepts – nothing is deleted or rewritten, so turning it off again
 * brings everything back. Deleting comments is the only thing here that cannot be undone, and it asks first.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Comments {

	const OPT   = 'empedia_cloud_comments';
	const BATCH = 200;

	public static function defaults() {
		return array(
			'mode'          => 'off', // off | all | types.
			'types'         => array(),
			'older_days'    => 0,
			'hide_existing' => 0,
			'pings'         => 0,
		);
	}

	public static function settings() {
		$o = get_option( self::OPT, array() );
		$o = is_array( $o ) ? array_merge( self::defaults(), $o ) : self::defaults();
		return array(
			'mode'          => in_array( $o['mode'], array( 'off', 'all', 'types' ), true ) ? $o['mode'] : 'off',
			'types'         => array_values( array_filter( array_map( 'sanitize_key', (array) $o['types'] ) ) ),
			'older_days'    => max( 0, min( 3650, (int) $o['older_days'] ) ),
			'hide_existing' => empty( $o['hide_existing'] ) ? 0 : 1,
			'pings'         => empty( $o['pings'] ) ? 0 : 1,
		);
	}

	/** Does the setting reach this post? */
	public static function covers( $post, $s = null ) {
		$s = $s ? $s : self::settings();
		if ( ! $post || empty( $post->post_type ) ) {
			return false;
		}
		if ( 'all' === $s['mode'] ) {
			return true;
		}
		if ( 'types' === $s['mode'] && in_array( $post->post_type, $s['types'], true ) ) {
			return true;
		}
		if ( $s['older_days'] > 0 && ! empty( $post->post_date_gmt ) && '0000-00-00 00:00:00' !== $post->post_date_gmt ) {
			$ts = strtotime( $post->post_date_gmt . ' UTC' );
			if ( $ts && $ts < time() - $s['older_days'] * DAY_IN_SECONDS ) {
				return true;
			}
		}
		return false;
	}

	/* ------------------------------------------------------------------ runtime */

	public static function init() {
		$s = self::settings();
		if ( 'off' === $s['mode'] && ! $s['older_days'] && ! $s['pings'] ) {
			return;
		}
		add_filter( 'comments_open', array( __CLASS__, 'filter_open' ), 99, 2 );
		add_filter( 'pings_open', array( __CLASS__, 'filter_pings' ), 99, 2 );
		if ( $s['pings'] ) {
			add_filter( 'pre_option_default_ping_status', array( __CLASS__, 'closed' ) );
			add_filter( 'wp_headers', array( __CLASS__, 'no_pingback_header' ) );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'xmlrpc_pings' ) );
		}
		if ( $s['hide_existing'] ) {
			add_filter( 'comments_array', array( __CLASS__, 'filter_array' ), 99, 2 );
			add_filter( 'get_comments_number', array( __CLASS__, 'filter_number' ), 99, 2 );
		}
		if ( 'off' !== $s['mode'] ) {
			add_action( 'init', array( __CLASS__, 'late' ), 100 );
		}
		if ( 'all' === $s['mode'] ) {
			add_filter( 'pre_option_default_comment_status', array( __CLASS__, 'closed' ) );
			add_filter( 'rest_endpoints', array( __CLASS__, 'rest' ) );
			add_filter( 'xmlrpc_methods', array( __CLASS__, 'xmlrpc_all' ) );
			add_filter( 'feed_links_show_comments_feed', '__return_false' );
			add_action( 'template_redirect', array( __CLASS__, 'comment_feed' ), 0 );
			add_action( 'widgets_init', array( __CLASS__, 'widgets' ), 20 );
			add_action( 'admin_menu', array( __CLASS__, 'menu' ), 999 );
			add_action( 'admin_init', array( __CLASS__, 'admin_redirect' ) );
			add_action( 'wp_before_admin_bar_render', array( __CLASS__, 'admin_bar' ) );
			add_action( 'wp_dashboard_setup', array( __CLASS__, 'dashboard' ), 20 );
		}
	}

	public static function closed() {
		return 'closed';
	}

	public static function filter_open( $open, $post_id ) {
		return $open && ! self::covers( get_post( $post_id ) ) ? true : false;
	}

	public static function filter_pings( $open, $post_id ) {
		$s = self::settings();
		if ( $s['pings'] ) {
			return false;
		}
		return $open && ! self::covers( get_post( $post_id ), $s ) ? true : false;
	}

	public static function filter_array( $comments, $post_id ) {
		return self::covers( get_post( $post_id ) ) ? array() : $comments;
	}

	public static function filter_number( $count, $post_id ) {
		return self::covers( get_post( $post_id ) ) ? 0 : $count;
	}

	public static function no_pingback_header( $headers ) {
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	public static function xmlrpc_pings( $methods ) {
		unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
		return $methods;
	}

	public static function xmlrpc_all( $methods ) {
		foreach ( array( 'wp.getComment', 'wp.getComments', 'wp.getCommentCount', 'wp.getCommentStatusList', 'wp.newComment', 'wp.editComment', 'wp.deleteComment' ) as $m ) {
			unset( $methods[ $m ] );
		}
		return $methods;
	}

	public static function rest( $endpoints ) {
		foreach ( array_keys( $endpoints ) as $route ) {
			if ( 0 === strpos( $route, '/wp/v2/comments' ) ) {
				unset( $endpoints[ $route ] );
			}
		}
		return $endpoints;
	}

	/** Content types no longer offer comments or trackbacks in the editor. */
	public static function late() {
		$s     = self::settings();
		$types = 'all' === $s['mode'] ? get_post_types( array(), 'names' ) : $s['types'];
		foreach ( $types as $type ) {
			remove_post_type_support( $type, 'comments' );
			remove_post_type_support( $type, 'trackbacks' );
		}
	}

	public static function comment_feed() {
		if ( is_comment_feed() ) {
			wp_safe_redirect( home_url( '/' ), 301 );
			exit;
		}
	}

	public static function widgets() {
		unregister_widget( 'WP_Widget_Recent_Comments' );
	}

	public static function menu() {
		remove_menu_page( 'edit-comments.php' );
		remove_submenu_page( 'options-general.php', 'options-discussion.php' );
	}

	public static function admin_redirect() {
		global $pagenow;
		if ( in_array( $pagenow, array( 'edit-comments.php', 'comment.php' ), true ) ) {
			wp_safe_redirect( admin_url() );
			exit;
		}
	}

	public static function admin_bar() {
		global $wp_admin_bar;
		if ( $wp_admin_bar ) {
			$wp_admin_bar->remove_menu( 'comments' );
		}
	}

	public static function dashboard() {
		remove_meta_box( 'dashboard_recent_comments', 'dashboard', 'normal' );
	}

	/* ------------------------------------------------------------------ cleaning up */

	/** The comment statuses of the cleanup tool, with the query value for get_comments(). */
	private static function statuses() {
		return array(
			'spam'     => array( __( 'Spam', 'empedia-shield' ), 'spam' ),
			'trash'    => array( __( 'Trash', 'empedia-shield' ), 'trash' ),
			'hold'     => array( __( 'Pending approval', 'empedia-shield' ), 'hold' ),
			'approved' => array( __( 'Approved', 'empedia-shield' ), 'approve' ),
		);
	}

	private static function query_args( array $status_keys, $older_days, $pings_only ) {
		$map  = self::statuses();
		$stat = array();
		foreach ( $status_keys as $k ) {
			if ( isset( $map[ $k ] ) ) {
				$stat[] = $map[ $k ][1];
			}
		}
		$args = array( 'status' => $stat, 'type' => $pings_only ? 'pings' : '', 'orderby' => 'comment_ID', 'order' => 'ASC' );
		if ( $older_days > 0 ) {
			$args['date_query'] = array( array( 'column' => 'comment_date_gmt', 'before' => gmdate( 'Y-m-d H:i:s', time() - $older_days * DAY_IN_SECONDS ) ) );
		}
		return $args;
	}

	public static function count( array $status_keys, $older_days = 0, $pings_only = false ) {
		if ( ! $status_keys ) {
			return 0;
		}
		return (int) get_comments( array_merge( self::query_args( $status_keys, $older_days, $pings_only ), array( 'count' => true ) ) );
	}

	/** Deletes up to BATCH comments per round for about 15 seconds. @return array{deleted:int,remaining:int} */
	public static function delete_batch( array $status_keys, $older_days, $pings_only ) {
		$deleted = 0;
		$stop    = time() + 15;
		wp_defer_comment_counting( true );
		do {
			$ids = get_comments( array_merge( self::query_args( $status_keys, $older_days, $pings_only ), array( 'fields' => 'ids', 'number' => self::BATCH ) ) );
			foreach ( $ids as $id ) {
				if ( wp_delete_comment( (int) $id, true ) ) {
					++$deleted;
				}
			}
		} while ( $ids && time() < $stop );
		wp_defer_comment_counting( false );
		return array( 'deleted' => $deleted, 'remaining' => self::count( $status_keys, $older_days, $pings_only ) );
	}

	/* ------------------------------------------------------------------ admin */

	public static function init_admin() {
		add_action( 'admin_post_empedia_cloud_comments_save', array( __CLASS__, 'handle_save' ) );
		add_action( 'admin_post_empedia_cloud_comments_delete', array( __CLASS__, 'handle_delete' ) );
		add_action( 'admin_post_empedia_cloud_comments_captcha', array( __CLASS__, 'handle_captcha' ) );
		add_action( 'wp_ajax_empedia_cloud_comments_check', array( __CLASS__, 'ajax_check' ) );
	}

	/** Capability check; every handler calls it first and then check_admin_referer() with its own nonce action. */
	private static function cap() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) || ! current_user_can( 'moderate_comments' ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
	}

	private static function back() {
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'comments' ) );
		exit;
	}

	public static function handle_save() {
		self::cap();
		check_admin_referer( 'empedia_cloud_comments_save' );
		$mode  = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : 'off';
		$types = isset( $_POST['types'] ) && is_array( $_POST['types'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['types'] ) ) : array();
		$valid = get_post_types( array(), 'names' );
		update_option(
			self::OPT,
			array(
				'mode'          => $mode,
				'types'         => array_values( array_intersect( $types, $valid ) ),
				'older_days'    => isset( $_POST['older_days'] ) ? (int) $_POST['older_days'] : 0,
				'hide_existing' => ! empty( $_POST['hide_existing'] ) ? 1 : 0,
				'pings'         => ! empty( $_POST['pings'] ) ? 1 : 0,
			),
			false
		);
		Empedia_Cloud_Plugin::schedule_soon();
		Empedia_Cloud_Admin::flash( 'success', __( 'Settings saved.', 'empedia-shield' ) );
		self::back();
	}

	public static function handle_delete() {
		self::cap();
		check_admin_referer( 'empedia_cloud_comments_delete' );
		$keys  = isset( $_POST['status'] ) && is_array( $_POST['status'] ) ? array_map( 'sanitize_key', wp_unslash( $_POST['status'] ) ) : array();
		$keys  = array_values( array_intersect( $keys, array_keys( self::statuses() ) ) );
		$days  = isset( $_POST['older_days'] ) ? max( 0, min( 3650, (int) $_POST['older_days'] ) ) : 0;
		$pings = ! empty( $_POST['pings_only'] );
		if ( ! $keys ) {
			Empedia_Cloud_Admin::flash( 'error', __( 'Choose which comments to delete.', 'empedia-shield' ) );
			self::back();
		}
		if ( in_array( 'approved', $keys, true ) && empty( $_POST['confirm'] ) ) {
			Empedia_Cloud_Admin::flash( 'error', __( 'Please confirm that approved comments may be deleted for good.', 'empedia-shield' ) );
			self::back();
		}
		$r = self::delete_batch( $keys, $days, $pings );
		if ( $r['remaining'] > 0 ) {
			/* translators: 1: deleted, 2: remaining */
			Empedia_Cloud_Admin::flash( 'warning', sprintf( __( '%1$d comments deleted, %2$d are left. Run the deletion again.', 'empedia-shield' ), $r['deleted'], $r['remaining'] ) );
		} else {
			/* translators: %d: number of comments */
			Empedia_Cloud_Admin::flash( 'success', sprintf( __( '%d comments deleted.', 'empedia-shield' ), $r['deleted'] ) );
		}
		self::back();
	}

	/** Quick switches for the new-comment protection of EMPEDIAcaptcha. */
	public static function handle_captcha() {
		self::cap();
		check_admin_referer( 'empedia_cloud_comments_captcha' );
		$o = get_option( 'empedia_captcha', array() );
		$o = is_array( $o ) ? $o : array();
		$o['forms']         = isset( $o['forms'] ) && is_array( $o['forms'] ) ? $o['forms'] : array();
		$o['forms']['comment'] = ! empty( $_POST['bot'] ) ? 1 : 0;
		$o['content_check'] = ! empty( $_POST['content'] ) ? 1 : 0;
		update_option( 'empedia_captcha', $o, false );
		Empedia_Cloud_Admin::flash( 'success', __( 'Settings saved.', 'empedia-shield' ) );
		self::back();
	}

	/** Checks the next comments after `last_id` with the content check; suspicious ones go to spam ( reversible ). */
	public static function ajax_check() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) || ! current_user_can( 'moderate_comments' ) || ! check_ajax_referer( 'empedia_cloud_comments', 'nonce', false ) ) {
			wp_send_json_error( array(), 403 );
		}
		if ( ! class_exists( 'Empedia_Captcha_Plugin' ) || ! method_exists( 'Empedia_Captcha_Plugin', 'check_text' ) ) {
			wp_send_json_error( array( 'code' => 'no_captcha' ), 400 );
		}
		global $wpdb;
		$scope = isset( $_POST['scope'] ) ? sanitize_key( wp_unslash( $_POST['scope'] ) ) : 'pending';
		$in    = 'approved' === $scope ? "'1'" : ( 'both' === $scope ? "'0','1'" : "'0'" ); // Constants only: comment_approved of pending / approved comments.
		$last  = isset( $_POST['last_id'] ) ? max( 0, (int) $_POST['last_id'] ) : 0;
		// Only comments by visitors, in ID order after the last one handled ( the cursor ).
		$ids = $wpdb->get_col( $wpdb->prepare( "SELECT comment_ID FROM {$wpdb->comments} WHERE comment_ID > %d AND comment_approved IN ( {$in} ) AND comment_type = 'comment' AND user_id = 0 ORDER BY comment_ID ASC LIMIT 10", $last ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL
		$checked = 0;
		$flagged = 0;
		foreach ( $ids as $id ) {
			$c = get_comment( (int) $id );
			if ( ! $c ) {
				$last = (int) $id;
				continue;
			}
			$r = Empedia_Captcha_Plugin::check_text(
				array(
					'email'   => $c->comment_author_email,
					'name'    => $c->comment_author,
					'message' => $c->comment_content,
					'ip'      => $c->comment_author_IP,
				)
			);
			if ( null === $r ) {
				wp_send_json_error( array( 'code' => 'no_captcha' ), 400 );
			}
			if ( $r['unreachable'] ) {
				wp_send_json_error( array( 'code' => 'unreachable', 'last_id' => $last ), 502 );
			}
			++$checked;
			$last = (int) $id;
			if ( 'allow' !== $r['verdict'] ) {
				wp_spam_comment( (int) $id );
				++$flagged;
			}
		}
		wp_send_json_success( array( 'done' => count( $ids ) < 10, 'last_id' => $last, 'checked' => $checked, 'flagged' => $flagged ) );
	}

	private static function row( $label, $html, $hint = '' ) {
		echo '<tr><th scope="row">' . esc_html( $label ) . '</th><td>' . $html . ( $hint ? '<p class="description">' . esc_html( $hint ) . '</p>' : '' ) . '</td></tr>'; // phpcs:ignore WordPress.Security.EscapeOutput
	}

	public static function render_tab() {
		$s = self::settings();
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Switch comments off', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Closes comments (and optionally trackbacks) without deleting anything: existing comments stay in the database, and turning this off brings everything back. Comments can also be closed for single posts in the editor.', 'empedia-shield' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_comments_save">';
		wp_nonce_field( 'empedia_cloud_comments_save' );
		echo '<table class="form-table" role="presentation">';
		$modes = array(
			'off'   => __( 'Leave comments as they are', 'empedia-shield' ),
			'all'   => __( 'Off everywhere (also hides the comments menu, feeds and the comments REST/XML-RPC interfaces)', 'empedia-shield' ),
			'types' => __( 'Off only for these content types:', 'empedia-shield' ),
		);
		$radios = '';
		foreach ( $modes as $k => $label ) {
			$radios .= '<label style="display:block;margin-bottom:4px"><input type="radio" name="mode" value="' . esc_attr( $k ) . '"' . checked( $s['mode'], $k, false ) . '> ' . esc_html( $label ) . '</label>';
		}
		$types = '<div style="margin:4px 0 0 24px">';
		foreach ( get_post_types( array( 'public' => true ), 'objects' ) as $pt ) {
			$types .= '<label style="display:inline-block;margin-right:16px"><input type="checkbox" name="types[]" value="' . esc_attr( $pt->name ) . '"' . checked( in_array( $pt->name, $s['types'], true ), true, false ) . '> ' . esc_html( $pt->labels->name ) . '</label>';
		}
		$types .= '</div>';
		self::row( __( 'Where', 'empedia-shield' ), $radios . $types );
		self::row( __( 'Old content', 'empedia-shield' ), '<label>' . esc_html__( 'Close comments on content older than', 'empedia-shield' ) . ' <input type="number" min="0" max="3650" name="older_days" value="' . esc_attr( (string) $s['older_days'] ) . '" style="width:80px"> ' . esc_html__( 'days (0 = never)', 'empedia-shield' ) . '</label>' );
		self::row( __( 'Existing comments', 'empedia-shield' ), '<label><input type="checkbox" name="hide_existing" value="1"' . checked( ! empty( $s['hide_existing'] ), true, false ) . '> ' . esc_html__( 'Also hide existing comments where comments are off', 'empedia-shield' ) . '</label>' );
		self::row( __( 'Pingbacks and trackbacks', 'empedia-shield' ), '<label><input type="checkbox" name="pings" value="1"' . checked( ! empty( $s['pings'] ), true, false ) . '> ' . esc_html__( 'Switch them off on the whole site (also stops pingback spam through XML-RPC)', 'empedia-shield' ) . '</label>' );
		echo '</table><p><button type="submit" class="button button-primary">' . esc_html__( 'Save', 'empedia-shield' ) . '</button></p></form></div>';

		// New comments: bot check and content check by EMPEDIAcaptcha.
		$cap_active = class_exists( 'Empedia_Captcha_Plugin' ) && method_exists( 'Empedia_Captcha_Plugin', 'check_text' );
		$cap        = $cap_active ? Empedia_Captcha_Plugin::opts() : array();
		$cap_ready  = $cap_active && ! empty( $cap['sitekey'] ) && ! empty( $cap['secret'] ) && ! empty( $cap['base'] );
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Check comments', 'empedia-shield' ) . '</h2>';
		if ( ! $cap_ready ) {
			echo '<p>' . esc_html__( 'Comments are checked for spam by EMPEDIAcaptcha: a bot check without puzzles for visitors and, optionally, a content check (from the Pro package). Set it up first.', 'empedia-shield' ) . '</p>';
			printf( '<p><a class="button button-primary" href="%s">%s</a></p></div>', esc_url( Empedia_Cloud_Admin::tab_url( 'bots' ) ), esc_html__( 'Set up bot protection', 'empedia-shield' ) );
		} else {
			echo '<h3>' . esc_html__( 'New comments', 'empedia-shield' ) . '</h3>';
			echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_comments_captcha">';
			wp_nonce_field( 'empedia_cloud_comments_captcha' );
			echo '<label style="display:block"><input type="checkbox" name="bot" value="1"' . checked( ! empty( $cap['forms']['comment'] ), true, false ) . '> ' . esc_html__( 'Bot check on the comment form', 'empedia-shield' ) . '</label>';
			echo '<label style="display:block;margin-top:4px"><input type="checkbox" name="content" value="1"' . checked( ! empty( $cap['content_check'] ), true, false ) . '> ' . esc_html__( 'Content check: suspicious comments are held as spam, clear abuse is rejected (Pro package, every check counts as a request)', 'empedia-shield' ) . '</label>';
			echo '<p><button type="submit" class="button">' . esc_html__( 'Save', 'empedia-shield' ) . '</button></p></form>';
			$hold = self::count( array( 'hold' ) );
			$appr = self::count( array( 'approved' ) );
			echo '<h3>' . esc_html__( 'Existing comments', 'empedia-shield' ) . '</h3>';
			echo '<p>' . esc_html__( 'Runs the content check over comments that are already there. Suspicious comments are moved to spam, not deleted, so you can restore them. Only comments by visitors are checked; every checked comment counts as one request of your EMPEDIAcaptcha package.', 'empedia-shield' ) . '</p>';
			echo '<p><label>' . esc_html__( 'Check', 'empedia-shield' ) . ' <select id="empedia-cc-scope">';
			/* translators: %d: number of comments */
			echo '<option value="pending">' . esc_html( sprintf( __( 'comments waiting for approval (%d)', 'empedia-shield' ), $hold ) ) . '</option>';
			/* translators: %d: number of comments */
			echo '<option value="approved">' . esc_html( sprintf( __( 'approved comments (%d)', 'empedia-shield' ), $appr ) ) . '</option>';
			/* translators: %d: number of comments */
			echo '<option value="both">' . esc_html( sprintf( __( 'both (%d)', 'empedia-shield' ), $hold + $appr ) ) . '</option>';
			echo '</select></label> <button type="button" class="button button-primary" id="empedia-cc-start">' . esc_html__( 'Check now', 'empedia-shield' ) . '</button> <span id="empedia-cc-msg" class="description"></span></p></div>';
			wp_enqueue_script( 'empedia-cloud-comments', EMPEDIA_CLOUD_URL_BASE . 'assets/comments.js', array(), EMPEDIA_CLOUD_VERSION, true );
			wp_localize_script(
				'empedia-cloud-comments',
				'EmpediaComments',
				array(
					'ajax'  => admin_url( 'admin-ajax.php' ),
					'nonce' => wp_create_nonce( 'empedia_cloud_comments' ),
					'i18n'  => array(
						/* translators: 1: checked, 2: suspicious */
						'progress'    => __( '%1$d checked, %2$d moved to spam …', 'empedia-shield' ),
						/* translators: 1: checked, 2: suspicious */
						'done'        => __( 'Done: %1$d checked, %2$d moved to spam.', 'empedia-shield' ),
						'unreachable' => __( 'The content check cannot be reached right now. Please try again later.', 'empedia-shield' ),
						'error'       => __( 'The request failed. Please try again.', 'empedia-shield' ),
						'confirm'     => __( 'Start the check? Every checked comment counts as one request of your EMPEDIAcaptcha package.', 'empedia-shield' ),
					),
				)
			);
		}

		// Clean up.
		$map = self::statuses();
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Delete comments', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Deletes comments for good – this cannot be undone. Make a backup first if you are unsure. Large amounts are deleted in rounds of about 15 seconds; run it again until nothing is left.', 'empedia-shield' ) . '</p>';
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" onsubmit="return window.confirm(' . esc_attr( wp_json_encode( __( 'Delete these comments for good?', 'empedia-shield' ) ) ) . ');"><input type="hidden" name="action" value="empedia_cloud_comments_delete">';
		wp_nonce_field( 'empedia_cloud_comments_delete' );
		echo '<table class="form-table" role="presentation">';
		$boxes = '';
		foreach ( $map as $k => $def ) {
			$boxes .= '<label style="display:block"><input type="checkbox" name="status[]" value="' . esc_attr( $k ) . '"' . checked( 'spam' === $k, true, false ) . '> ' . esc_html( $def[0] ) . ' <span class="description">(' . (int) self::count( array( $k ) ) . ')</span></label>';
		}
		self::row( __( 'Which comments', 'empedia-shield' ), $boxes );
		self::row( __( 'Older than', 'empedia-shield' ), '<input type="number" min="0" max="3650" name="older_days" value="0" style="width:80px"> ' . esc_html__( 'days (0 = every age)', 'empedia-shield' ) );
		self::row( __( 'Kind', 'empedia-shield' ), '<label><input type="checkbox" name="pings_only" value="1"> ' . esc_html__( 'Only pingbacks and trackbacks', 'empedia-shield' ) . '</label>' );
		self::row( __( 'Approved comments', 'empedia-shield' ), '<label><input type="checkbox" name="confirm" value="1"> ' . esc_html__( 'I know that approved comments are deleted for good (required when “Approved” is ticked)', 'empedia-shield' ) . '</label>' );
		echo '</table><p><button type="submit" class="button">' . esc_html__( 'Delete comments', 'empedia-shield' ) . '</button></p></form></div>';
	}
}
