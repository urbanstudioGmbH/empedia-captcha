<?php
/**
 * Tab “Firewall”: switch on in observe mode, per-class modes, lists, samples, must-use loader.
 *
 * @package EmpediaCloud
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Empedia_Cloud_Firewall_Admin {

	public static function init() {
		foreach ( array( 'toggle', 'save', 'legit', 'mu' ) as $a ) {
			add_action( 'admin_post_empedia_cloud_fw_' . $a, array( __CLASS__, 'handle_' . $a ) );
		}
	}

	/** Capability check; every handler calls it first and then check_admin_referer() with its own nonce action. */
	private static function cap() {
		if ( ! current_user_can( Empedia_Cloud_Admin::CAP ) ) {
			wp_die( esc_html__( 'You are not allowed to do this.', 'empedia-shield' ), '', array( 'response' => 403 ) );
		}
	}

	private static function back( $type = '', $text = '' ) {
		if ( $text ) {
			Empedia_Cloud_Admin::flash( $type, $text );
		}
		wp_safe_redirect( Empedia_Cloud_Admin::tab_url( 'firewall' ) );
		exit;
	}

	public static function class_labels() {
		return array(
			'sqli'    => __( 'SQL injection', 'empedia-shield' ),
			'xss'     => __( 'Script injection (XSS)', 'empedia-shield' ),
			'lfi'     => __( 'File inclusion and path traversal', 'empedia-shield' ),
			'upload'  => __( 'PHP uploads (visitors)', 'empedia-shield' ),
			'scanner' => __( 'Known attack tools', 'empedia-shield' ),
			'probe'   => __( 'Probing for sensitive files', 'empedia-shield' ),
			'xmlrpc'  => __( 'XML-RPC abuse', 'empedia-shield' ),
			'rate'    => __( 'Too many requests (sign-in, XML-RPC)', 'empedia-shield' ),
			'ip'      => __( 'Blocked addresses and countries', 'empedia-shield' ),
		);
	}

	public static function handle_toggle() {
		self::cap();
		check_admin_referer( 'empedia_cloud_fw_toggle' );
		$s = Empedia_Cloud_Firewall::settings();
		if ( ! empty( $_POST['on'] ) ) {
			$s['enabled'] = true;
			foreach ( Empedia_Cloud_Firewall::classes() as $c ) {
				$s['since'][ $c ] = time(); // switching on starts a new observation period
				if ( 'enforce' === $s['modes'][ $c ] && 'ip' !== $c ) {
					$s['modes'][ $c ] = 'observe';
				}
			}
			update_option( Empedia_Cloud_Firewall::OPTION, $s, false );
			self::back( 'success', __( 'The firewall is on. All rules only report (observe mode); nothing is blocked yet.', 'empedia-shield' ) );
		}
		$s['enabled'] = false;
		update_option( Empedia_Cloud_Firewall::OPTION, $s, false );
		self::back( 'success', __( 'The firewall is off.', 'empedia-shield' ) );
	}

	private static function list_clean( $v, $kind ) {
		$items = preg_split( '/[\s,;]+/', (string) $v, -1, PREG_SPLIT_NO_EMPTY );
		$out   = array();
		foreach ( $items as $i ) {
			if ( 'cc' === $kind ) {
				if ( preg_match( '/^[A-Za-z]{2}$/', $i ) ) {
					$out[] = strtoupper( $i );
				}
			} else {
				$base = explode( '/', $i )[0];
				if ( filter_var( $base, FILTER_VALIDATE_IP ) && ( false === strpos( $i, '/' ) || preg_match( '#^[^/]+/\d{1,3}$#', $i ) ) ) {
					$bits = false === strpos( $i, '/' ) ? 128 : (int) explode( '/', $i )[1];
					$min  = false === strpos( $base, ':' ) ? 8 : 16; // very wide ranges would lock out half the internet
					if ( $bits >= $min ) {
						$out[] = $i;
					}
				}
			}
		}
		return implode( "\n", array_slice( array_unique( $out ), 0, 500 ) );
	}

	public static function handle_save() {
		self::cap();
		check_admin_referer( 'empedia_cloud_fw_save' );
		$p   = wp_unslash( $_POST ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		$s   = Empedia_Cloud_Firewall::settings();
		$msg = '';
		foreach ( Empedia_Cloud_Firewall::classes() as $c ) {
			$want = isset( $p['mode'][ $c ] ) && in_array( $p['mode'][ $c ], array( 'off', 'observe', 'enforce' ), true ) ? $p['mode'][ $c ] : $s['modes'][ $c ];
			if ( 'enforce' === $want && 'enforce' !== $s['modes'][ $c ] && 'ip' !== $c ) {
				// Blocking only after a period of observation ( false positives are seen first ), unless confirmed explicitly.
				$since = isset( $s['since'][ $c ] ) ? (int) $s['since'][ $c ] : 0;
				if ( ( ! $since || time() - $since < Empedia_Cloud_Firewall::MIN_OBSERVE ) && empty( $p['confirm_early'][ $c ] ) ) {
					$want = $s['modes'][ $c ];
					$msg  = __( 'A rule group can only start blocking after 72 hours of observation. Tick “block anyway” to override.', 'empedia-shield' );
				}
			}
			if ( 'off' === $want ) {
				unset( $s['since'][ $c ] ); // a group that was off must be observed again before it may block
			} elseif ( 'observe' === $want && 'observe' !== $s['modes'][ $c ] || empty( $s['since'][ $c ] ) ) {
				$s['since'][ $c ] = time();
			}
			$s['modes'][ $c ] = $want;
		}
		$s['allow_ips']       = self::list_clean( isset( $p['allow_ips'] ) ? $p['allow_ips'] : '', 'ip' );
		$s['block_ips']       = self::list_clean( isset( $p['block_ips'] ) ? $p['block_ips'] : '', 'ip' );
		$s['allow_countries'] = self::list_clean( isset( $p['allow_countries'] ) ? $p['allow_countries'] : '', 'cc' );
		$s['block_countries'] = self::list_clean( isset( $p['block_countries'] ) ? $p['block_countries'] : '', 'cc' );
		// Never lock the owner out: the own address and country must not match the lists.
		$me = Empedia_Cloud_Firewall::client_ip();
		if ( Empedia_Cloud_Firewall::ip_in( $me, $s['block_ips'] ) ) {
			$s['block_ips'] = implode( "\n", array_filter( explode( "\n", $s['block_ips'] ), function ( $e ) use ( $me ) {
				return ! Empedia_Cloud_Firewall::ip_in( $me, $e );
			} ) );
			$msg = __( 'Your own address was removed from the blocked addresses.', 'empedia-shield' );
		}
		$cc = Empedia_Cloud_Firewall::country_of_request();
		if ( '' !== $cc ) {
			$bl = array_filter( explode( "\n", $s['block_countries'] ) );
			$al = array_filter( explode( "\n", $s['allow_countries'] ) );
			if ( in_array( $cc, $bl, true ) ) {
				$s['block_countries'] = implode( "\n", array_diff( $bl, array( $cc ) ) );
				$msg                  = __( 'Your own country was removed from the blocked countries.', 'empedia-shield' );
			}
			if ( $al && ! in_array( $cc, $al, true ) ) {
				$s['allow_countries'] = implode( "\n", array_merge( $al, array( $cc ) ) );
				$msg                  = __( 'Your own country was added to the allowed countries.', 'empedia-shield' );
			}
		}
		if ( isset( $p['clear_exceptions'] ) ) {
			$s['exceptions'] = array();
		}
		update_option( Empedia_Cloud_Firewall::OPTION, $s, false );
		Empedia_Cloud_Plugin::schedule_soon();
		self::back( $msg ? 'warning' : 'success', $msg ? $msg : __( 'Settings saved.', 'empedia-shield' ) );
	}

	public static function handle_legit() {
		self::cap();
		check_admin_referer( 'empedia_cloud_fw_legit' );
		$id = isset( $_POST['sample'] ) ? preg_replace( '/[^a-f0-9]/', '', (string) wp_unslash( $_POST['sample'] ) ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
		if ( Empedia_Cloud_Firewall::mark_legit( $id ) ) {
			Empedia_Cloud_Plugin::schedule_soon();
			self::back( 'success', __( 'Noted: this kind of request is no longer reported by this rule.', 'empedia-shield' ) );
		}
		self::back( 'error', __( 'The sample is no longer available.', 'empedia-shield' ) );
	}

	public static function handle_mu() {
		self::cap();
		check_admin_referer( 'empedia_cloud_fw_mu' );
		if ( ! empty( $_POST['install'] ) ) {
			if ( Empedia_Cloud_Firewall::install_mu() ) {
				self::back( 'success', __( 'The firewall now loads before other plugins.', 'empedia-shield' ) );
			}
			self::back( 'error', __( 'The folder wp-content/mu-plugins cannot be created or written by WordPress. Nothing was changed. The firewall keeps running as a normal plugin; if you want the early start, create the file by hand or ask your host to make the folder writable.', 'empedia-shield' ) );
		}
		Empedia_Cloud_Firewall::remove_mu();
		self::back( 'success', __( 'The early loader was removed.', 'empedia-shield' ) );
	}

	private static function post_form( $action, $fields, $label, $class = 'button' ) {
		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '" style="display:inline">';
		echo '<input type="hidden" name="action" value="' . esc_attr( $action ) . '">';
		foreach ( $fields as $k => $v ) {
			echo '<input type="hidden" name="' . esc_attr( $k ) . '" value="' . esc_attr( $v ) . '">';
		}
		wp_nonce_field( $action );
		echo '<button type="submit" class="' . esc_attr( $class ) . '">' . esc_html( $label ) . '</button></form>';
	}

	public static function render_tab() {
		$s      = Empedia_Cloud_Firewall::settings();
		$remote = Empedia_Cloud_Firewall::remote();
		$stats  = Empedia_Cloud_Firewall::stats( 7 );
		$legit  = Empedia_Cloud_Firewall::legit_counts();
		$labels = self::class_labels();
		$ids    = Empedia_Cloud_Firewall::rule_ids();

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Firewall', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Checks every request very early for typical attacks (SQL injection, scripts in addresses and forms, file inclusion, PHP uploads by visitors, known attack tools, probing for sensitive files, XML-RPC abuse, too many requests, blocked addresses). Every rule group starts in observe mode: matches are only counted and sampled, nothing is blocked. After at least 72 hours without false alarms you can let a group block (answer 403). IP addresses are never stored.', 'empedia-shield' ) . '</p>';
		if ( Empedia_Cloud_Firewall::off_by_constant() ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The firewall is switched off by EMPEDIA_CLOUD_FIREWALL_OFF in wp-config.php.', 'empedia-shield' ) . '</p></div>';
		}
		if ( 'off' === $remote['switch'] ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'The firewall was paused in EMPEDIAcloud (emergency switch).', 'empedia-shield' ) . '</p></div>';
		} elseif ( 'observe' === $remote['switch'] ) {
			echo '<div class="notice notice-warning inline"><p>' . esc_html__( 'Blocking was paused in EMPEDIAcloud: all rules only observe.', 'empedia-shield' ) . '</p></div>';
		}
		echo '<p>';
		if ( $s['enabled'] ) {
			echo '<span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> ' . esc_html__( 'The firewall is on.', 'empedia-shield' ) . ' ';
			self::post_form( 'empedia_cloud_fw_toggle', array( 'on' => '' ), __( 'Switch off', 'empedia-shield' ) );
		} else {
			self::post_form( 'empedia_cloud_fw_toggle', array( 'on' => '1' ), __( 'Switch on (observe mode)', 'empedia-shield' ), 'button button-primary' );
		}
		echo '</p>';
		echo '<p class="description">' . esc_html__( 'Emergency exit: add define( \'EMPEDIA_CLOUD_FIREWALL_OFF\', true ); to wp-config.php. A class that blocks more than 300 requests in a minute pauses itself for 30 minutes.', 'empedia-shield' ) . '</p></div>';

		echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="empedia_cloud_fw_save">';
		wp_nonce_field( 'empedia_cloud_fw_save' );
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Rule groups', 'empedia-shield' ) . '</h2><table class="widefat striped"><thead><tr><th>' . esc_html__( 'Group', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Mode', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Last 7 days', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Observed for', 'empedia-shield' ) . '</th></tr></thead><tbody>';
		foreach ( Empedia_Cloud_Firewall::classes() as $c ) {
			$obs = 0;
			$blk = 0;
			$lg  = 0;
			foreach ( $ids as $rid => $rc ) {
				if ( $rc === $c ) {
					$obs += isset( $stats[ $rid ] ) ? $stats[ $rid ][0] : 0;
					$blk += isset( $stats[ $rid ] ) ? $stats[ $rid ][1] : 0;
					$lg  += isset( $legit[ $rid ] ) ? (int) $legit[ $rid ] : 0;
				}
			}
			$since = isset( $s['since'][ $c ] ) ? (int) $s['since'][ $c ] : 0;
			$hours = $since ? (int) floor( ( time() - $since ) / HOUR_IN_SECONDS ) : 0;
			$ready = $since && time() - $since >= Empedia_Cloud_Firewall::MIN_OBSERVE;
			echo '<tr><td><strong>' . esc_html( $labels[ $c ] ) . '</strong></td><td><select name="mode[' . esc_attr( $c ) . ']">';
			foreach ( array( 'off' => __( 'Off', 'empedia-shield' ), 'observe' => __( 'Observe only', 'empedia-shield' ), 'enforce' => __( 'Block', 'empedia-shield' ) ) as $k => $l ) {
				echo '<option value="' . esc_attr( $k ) . '"' . selected( $s['modes'][ $c ], $k, false ) . '>' . esc_html( $l ) . '</option>';
			}
			echo '</select>';
			if ( 'ip' !== $c && ! $ready && 'enforce' !== $s['modes'][ $c ] ) {
				echo '<br><label class="description"><input type="checkbox" name="confirm_early[' . esc_attr( $c ) . ']" value="1"> ' . esc_html__( 'block anyway (less than 72 hours observed)', 'empedia-shield' ) . '</label>';
			}
			echo '</td><td>';
			/* translators: 1: matches observed, 2: requests blocked, 3: marked legitimate */
			echo esc_html( sprintf( __( '%1$d matches, %2$d blocked, %3$d marked legitimate', 'empedia-shield' ), $obs, $blk, $lg ) );
			echo '</td><td>' . esc_html( $since ? sprintf( /* translators: %d: hours */ _n( '%d hour', '%d hours', $hours, 'empedia-shield' ), $hours ) : '—' ) . '</td></tr>';
		}
		echo '</tbody></table></div>';

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Addresses and countries', 'empedia-shield' ) . '</h2><table class="form-table" role="presentation">';
		echo '<tr><th>' . esc_html__( 'Never inspect these addresses', 'empedia-shield' ) . '</th><td><textarea name="allow_ips" rows="3" cols="40" class="code">' . esc_textarea( $s['allow_ips'] ) . '</textarea><p class="description">' . esc_html__( 'One address or range (CIDR) per line, for example your office.', 'empedia-shield' ) . '</p></td></tr>';
		echo '<tr><th>' . esc_html__( 'Always block these addresses', 'empedia-shield' ) . '</th><td><textarea name="block_ips" rows="3" cols="40" class="code">' . esc_textarea( $s['block_ips'] ) . '</textarea></td></tr>';
		echo '<tr><th>' . esc_html__( 'Block these countries', 'empedia-shield' ) . '</th><td><input type="text" name="block_countries" value="' . esc_attr( str_replace( "\n", ' ', $s['block_countries'] ) ) . '" placeholder="RU CN" class="regular-text"></td></tr>';
		echo '<tr><th>' . esc_html__( 'Allow only these countries', 'empedia-shield' ) . '</th><td><input type="text" name="allow_countries" value="' . esc_attr( str_replace( "\n", ' ', $s['allow_countries'] ) ) . '" placeholder="DE AT CH" class="regular-text"><p class="description">' . esc_html__( 'Country rules need a header from your CDN or server (for example CF-IPCountry from Cloudflare); without such a header they do nothing. They follow the mode of the group “Blocked addresses and countries”.', 'empedia-shield' ) . '</p></td></tr>';
		if ( $s['exceptions'] ) {
			/* translators: %d: number of exceptions */
			echo '<tr><th>' . esc_html__( 'Exceptions', 'empedia-shield' ) . '</th><td><label><input type="checkbox" name="clear_exceptions" value="1"> ' . esc_html( sprintf( __( 'Remove all %d exceptions marked as legitimate', 'empedia-shield' ), count( $s['exceptions'] ) ) ) . '</label></td></tr>';
		}
		echo '</table></div><p><button type="submit" class="button button-primary">' . esc_html__( 'Save settings', 'empedia-shield' ) . '</button></p></form>';

		$samples = Empedia_Cloud_Firewall::samples();
		echo '<div class="empedia-card"><h2>' . esc_html__( 'Latest matches', 'empedia-shield' ) . '</h2>';
		if ( ! $samples ) {
			echo '<p class="description">' . esc_html__( 'No matches yet.', 'empedia-shield' ) . '</p>';
		} else {
			echo '<p class="description">' . esc_html__( 'A few samples per rule and minute. If a request was legitimate, mark it: the rule then stays quiet for this field and the cloud counts it as a false alarm.', 'empedia-shield' ) . '</p><table class="widefat striped"><thead><tr><th>' . esc_html__( 'Time', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Rule', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Field', 'empedia-shield' ) . '</th><th>' . esc_html__( 'Excerpt', 'empedia-shield' ) . '</th><th></th></tr></thead><tbody>';
			foreach ( array_slice( $samples, 0, 40 ) as $m ) {
				echo '<tr><td>' . esc_html( wp_date( 'd.m. H:i', (int) $m['t'] ) ) . ( ! empty( $m['b'] ) ? ' <span class="dashicons dashicons-shield" title="' . esc_attr__( 'blocked', 'empedia-shield' ) . '"></span>' : '' ) . '</td><td><code>' . esc_html( $m['rule'] ) . '</code></td><td><code>' . esc_html( $m['f'] ) . '</code></td><td><code>' . esc_html( $m['x'] ) . '</code></td><td style="text-align:right">';
				self::post_form( 'empedia_cloud_fw_legit', array( 'sample' => $m['id'] ), __( 'Legitimate', 'empedia-shield' ), 'button-link' );
				echo '</td></tr>';
			}
			echo '</tbody></table>';
		}
		echo '</div>';

		echo '<div class="empedia-card"><h2>' . esc_html__( 'Early start (optional)', 'empedia-shield' ) . '</h2>';
		echo '<p>' . esc_html__( 'Plugins that load before this plugin have already processed a request when the firewall runs. If you want the firewall to run first, you can install a small “must-use” file. This is optional and only happens when you click the button.', 'empedia-shield' ) . '</p>';
		echo '<p class="description">' . esc_html__( 'What the button does: it writes one small file (empedia-shield-firewall.php) into the folder wp-content/mu-plugins. The file has a fixed content and does nothing but load the firewall of this plugin first. The button “Remove early loader” deletes it again; it is also removed when you deactivate or delete the plugin. Without it, the firewall works as a normal plugin.', 'empedia-shield' ) . '</p><p>';
		if ( Empedia_Cloud_Firewall::mu_installed() ) {
			echo '<span class="dashicons dashicons-yes-alt" style="color:#00a32a"></span> ' . esc_html__( 'The early loader is installed.', 'empedia-shield' ) . ' ';
			self::post_form( 'empedia_cloud_fw_mu', array( 'install' => '' ), __( 'Remove early loader', 'empedia-shield' ) );
		} else {
			if ( Empedia_Cloud_Firewall::mu_legacy_installed() ) {
				echo esc_html__( 'An early loader of an earlier version is installed. Installing the new one replaces it.', 'empedia-shield' ) . ' ';
				self::post_form( 'empedia_cloud_fw_mu', array( 'install' => '' ), __( 'Remove early loader', 'empedia-shield' ) );
				echo ' ';
			}
			self::post_form( 'empedia_cloud_fw_mu', array( 'install' => '1' ), __( 'Install early loader', 'empedia-shield' ) );
		}
		echo '</p></div>';
	}
}
