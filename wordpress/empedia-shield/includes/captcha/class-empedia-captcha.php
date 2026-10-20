<?php
/**
 * Bot protection (EMPEDIAcaptcha) as a module of EMPEDIA Shield: login, registration, password reset, comments,
 * Contact Form 7 and WooCommerce, optional page gate. Works without a connection to EMPEDIAcloud: enter the keys by hand
 * or let the tab "Bot protection" set them up when the site is connected.
 *
 * @package EmpediaCloud
 */

if (!defined('ABSPATH')) { exit; }

// Never declare the classes twice (the former stand-alone plugin EMPEDIAcaptcha may still be around): all declarations are conditional.
if (!class_exists('Empedia_Captcha_Plugin', false)) {
    require_once EMPEDIA_CLOUD_DIR . 'lib/empedia-captcha/Client.php';
    require_once EMPEDIA_CLOUD_DIR . 'lib/empedia-captcha/VerifyResult.php';
    require_once EMPEDIA_CLOUD_DIR . 'lib/empedia-captcha/CheckResult.php';
    require_once EMPEDIA_CLOUD_DIR . 'includes/captcha/class-empedia-captcha-http.php';
    require_once EMPEDIA_CLOUD_DIR . 'includes/captcha/class-empedia-gate.php';
}

use Empedia\Captcha\Client;

if (!class_exists('Empedia_Captcha_Plugin', false)) {

final class Empedia_Captcha_Plugin
{
    const OPT = 'empedia_captcha';
    private static $instance;
    private $printed = false;

    public static function boot(): void
    {
        if (!self::$instance) { self::$instance = new self(); }
    }

    public static function defaults(): array
    {
        return ['base' => '', 'sitekey' => '', 'secret' => '', 'fail_open' => 1, 'content_check' => 0, 'gate' => 0,
            'forms' => ['login' => 1, 'register' => 1, 'lostpassword' => 1, 'comment' => 1, 'cf7' => 1, 'woo' => 1]];
    }

    public static function opts(): array
    {
        $o = get_option(self::OPT, []);
        $d = self::defaults();
        $o = is_array($o) ? array_merge($d, $o) : $d;
        $o['forms'] = array_merge($d['forms'], is_array($o['forms'] ?? null) ? $o['forms'] : []);
        foreach (['EMPEDIA_CAPTCHA_BASE' => 'base', 'EMPEDIA_CAPTCHA_SITEKEY' => 'sitekey', 'EMPEDIA_CAPTCHA_SECRET' => 'secret'] as $const => $key) {
            if (defined($const) && constant($const) !== '') { $o[$key] = (string) constant($const); $o['_const_' . $key] = true; }
        }
        return $o;
    }

    /** Emergency exit: define( 'EMPEDIA_CAPTCHA_OFF', true ); in wp-config.php switches every check and the page gate off. */
    public static function off(): bool
    {
        return defined('EMPEDIA_CAPTCHA_OFF') && EMPEDIA_CAPTCHA_OFF;
    }

    public function configured(): bool
    {
        if (self::off()) { return false; }
        $o = self::opts();
        return $o['base'] !== '' && $o['sitekey'] !== '' && $o['secret'] !== '';
    }

    private function client(): Client
    {
        $o = self::opts();
        // All requests go through the WordPress HTTP API (Empedia_Captcha_Http), the SDK's own cURL transport is not part of the plugin.
        return new Client($o['sitekey'], $o['secret'], $o['base'], ['failOpen' => !empty($o['fail_open']), 'timeout' => 4.0, 'transport' => ['Empedia_Captcha_Http', 'send']]);
    }

    private function on(string $form): bool
    {
        $o = self::opts();
        return $this->configured() && !empty($o['forms'][$form]);
    }

    private function __construct()
    {
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_enqueue_scripts', [$this, 'maybe_script']);
        add_action('login_enqueue_scripts', [$this, 'maybe_script']);

        // Anmeldung, Registrierung, Passwort vergessen
        add_action('login_form', function () { $this->field('login', 'login'); });
        add_filter('authenticate', [$this, 'check_login'], 30, 3);
        add_action('register_form', function () { $this->field('register', 'register'); });
        add_filter('registration_errors', [$this, 'check_register'], 10, 3);
        add_action('lostpassword_form', function () { $this->field('lostpassword', 'lostpassword'); });
        add_action('lostpassword_post', [$this, 'check_lostpassword'], 10, 1);

        // Kommentare
        add_filter('comment_form_submit_field', function ($html) { return $this->on('comment') ? $this->element('comment') . $html : $html; });
        add_filter('preprocess_comment', [$this, 'check_comment']);

        // WooCommerce
        add_action('woocommerce_login_form', function () { $this->field('woo', 'login'); });
        add_action('woocommerce_register_form', function () { $this->field('woo', 'register'); });
        add_action('woocommerce_lostpassword_form', function () { $this->field('woo', 'lostpassword'); });
        add_action('woocommerce_review_order_before_submit', function () { $this->field('woo', 'checkout'); });
        add_action('woocommerce_after_checkout_validation', [$this, 'check_checkout'], 10, 2);
        add_filter('woocommerce_process_registration_errors', [$this, 'check_woo_register'], 10, 1);
        add_filter('render_block_woocommerce/checkout-actions-block', [$this, 'block_checkout_field']);
        add_filter('rest_pre_dispatch', [$this, 'check_block_checkout'], 10, 3);

        // Contact Form 7
        add_filter('wpcf7_form_elements', [$this, 'cf7_inject']);
        add_filter('wpcf7_spam', [$this, 'cf7_spam'], 9, 2);
    }

    /* ---------- Widget ---------- */

    private function element(string $action): string
    {
        $o = self::opts();
        $this->printed = true;
        return '<div class="empedia-captcha" data-sitekey="' . esc_attr($o['sitekey']) . '" data-action="' . esc_attr($action) . '" data-mode="submit"></div>';
    }

    /** Output filter for the widget element: only the one div with its data attributes. */
    private static function allowed_html(): array
    {
        return ['div' => ['class' => true, 'data-sitekey' => true, 'data-action' => true, 'data-mode' => true, 'data-badge' => true]];
    }

    private function field(string $form, string $action): void
    {
        if ($this->on($form)) { echo wp_kses($this->element($action), self::allowed_html()); }
    }

    public function maybe_script(): void
    {
        if (!$this->configured()) { return; }
        $o = self::opts();
        wp_enqueue_script('empedia-shield', rtrim($o['base'], '/') . '/captcha/v1/widget.js', [], EMPEDIA_CLOUD_VERSION, ['strategy' => 'defer', 'in_footer' => true]);
        // Token ist einmalig: nach einem abgelehnten WooCommerce-Checkout neu anfordern
        wp_add_inline_script('empedia-shield', "if(window.jQuery){window.jQuery(document.body).on('checkout_error',function(){if(window.EmpediaCaptcha&&window.EmpediaCaptcha.reset){window.EmpediaCaptcha.reset();}});}", 'after');
    }

    /* ---------- Checks ---------- */

    private function token(): string
    {
        // The form belongs to WordPress core, WooCommerce or Contact Form 7 (they verify their own nonces); the token is verified by the service.
        // phpcs:ignore WordPress.Security.NonceVerification.Missing
        return isset($_POST[Client::TOKEN_FIELD]) ? sanitize_text_field(wp_unslash($_POST[Client::TOKEN_FIELD])) : '';
    }

    private function ok(string $action): bool
    {
        $r = $this->client()->verify($this->token(), $action);
        if (!$r->success) { self::note_fail($action, $r->errorCodes); }
        return $r->success;
    }

    /** Remembers why a check was refused ( last 10, no personal data ), shown on the settings page. */
    private static function note_fail(string $action, array $codes): void
    {
        $l = get_option('empedia_captcha_fails', []);
        $l = is_array($l) ? $l : [];
        array_unshift($l, ['t' => time(), 'a' => $action, 'c' => substr(implode(',', array_map('sanitize_key', array_slice($codes, 0, 3))), 0, 80)]);
        update_option('empedia_captcha_fails', array_slice($l, 0, 10), false);
    }

    private function msg(): string
    {
        return __('The security check failed. Please try again.', 'empedia-shield');
    }

    public function check_login($user, $username, $password)
    {
        // Only looks at whether core's sign-in form (or WooCommerce's) was posted; the credentials are not read here.
        // phpcs:disable WordPress.Security.NonceVerification.Missing
        if (!$this->on('login') || empty($_POST) || $username === '' || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) || (defined('REST_REQUEST') && REST_REQUEST)) { return $user; }
        if (!isset($_POST['log']) && !isset($_POST['username'])) { return $user; }
        // phpcs:enable WordPress.Security.NonceVerification.Missing
        return $this->ok('login') ? $user : new WP_Error('empedia_captcha', $this->msg());
    }

    public function check_register($errors, $login, $email)
    {
        if ($this->on('register') && !$this->ok('register')) { $errors->add('empedia_captcha', $this->msg()); }
        return $errors;
    }

    public function check_woo_register($errors)
    {
        if ($this->on('woo') && !$this->ok('register')) { return new WP_Error('empedia_captcha', $this->msg()); }
        return $errors;
    }

    public function check_lostpassword($errors)
    {
        if ($this->on('lostpassword') && !$this->ok('lostpassword') && $errors instanceof WP_Error) { $errors->add('empedia_captcha', $this->msg()); }
    }

    public function check_checkout($data, $errors)
    {
        if ($this->on('woo') && !$this->ok('checkout')) { $errors->add('empedia_captcha', $this->msg()); }
    }

    /** The Checkout block does not call the classic WooCommerce checkout hooks. */
    public function block_checkout_field($content)
    {
        if (is_admin() || !$this->on('woo')) { return $content; }
        wp_enqueue_script('empedia-shield-woo-blocks', EMPEDIA_CLOUD_URL_BASE . 'assets/captcha-woo-blocks.js', ['empedia-shield', 'wp-data'], EMPEDIA_CLOUD_VERSION, ['strategy' => 'defer', 'in_footer' => true]);
        return $this->element('checkout') . $content;
    }

    /** Reject direct Store API checkout requests without a valid proof, before an order is processed. */
    public function check_block_checkout($result, $server, $request)
    {
        if (is_wp_error($result) || !$this->on('woo') || $request->get_method() !== 'POST' ||
            !preg_match('#^/wc/store(?:/v[0-9]+)?/checkout/?$#', $request->get_route())) { return $result; }
        $body = $request->get_json_params();
        $token = is_array($body) && isset($body['extensions']['empedia-shield']['token']) && is_string($body['extensions']['empedia-shield']['token'])
            ? sanitize_text_field($body['extensions']['empedia-shield']['token']) : '';
        $r = $this->client()->verify($token, 'checkout');
        if ($r->success) { return $result; }
        self::note_fail('checkout', $r->errorCodes);
        return new WP_Error('empedia_captcha', $this->msg(), ['status' => 403]);
    }

    /**
     * Content check of one text for other plugins ( EMPEDIAcloud: “check existing comments” ), independent of the “content check” setting.
     * Returns array( 'verdict' => allow|review|block, 'unreachable' => bool ), or null while the plugin is not configured.
     */
    public static function check_text(array $fields)
    {
        if (!self::$instance || !self::$instance->configured()) { return null; }
        $r = self::$instance->client()->check($fields);
        return ['verdict' => $r->verdict, 'unreachable' => $r->unreachable];
    }

    private function contentVerdict(array $fields): string
    {
        $o = self::opts();
        if (empty($o['content_check'])) { return 'allow'; }
        $fields['ip'] = $this->ip();
        return $this->client()->check($fields)->verdict;
    }

    private function ip(): string
    {
        return isset($_SERVER['REMOTE_ADDR']) ? sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'])) : '';
    }

    public function check_comment($c)
    {
        if (!$this->on('comment') || is_user_logged_in() || in_array($c['comment_type'] ?? '', ['pingback', 'trackback'], true)) { return $c; }
        if (!$this->ok('comment')) { wp_die(esc_html($this->msg()), '', ['response' => 400, 'back_link' => true]); }
        $v = $this->contentVerdict(['email' => $c['comment_author_email'] ?? '', 'name' => $c['comment_author'] ?? '', 'message' => $c['comment_content'] ?? '']);
        if ($v === 'block') { wp_die(esc_html($this->msg()), '', ['response' => 400, 'back_link' => true]); }
        if ($v === 'review') { add_filter('pre_comment_approved', function () { return 'spam'; }); }
        return $c;
    }

    /* ---------- Contact Form 7 ---------- */

    public function cf7_inject($html)
    {
        return $this->on('cf7') ? $html . $this->element('contact') : $html;
    }

    public function cf7_spam($spam, $submission = null)
    {
        if ($spam || !$this->on('cf7')) { return $spam; }
        if (!$this->ok('contact')) { return true; }
        $post = $submission && method_exists($submission, 'get_posted_data') ? (array) $submission->get_posted_data() : [];
        $pick = function (array $keys) use ($post) { foreach ($keys as $k) { if (!empty($post[$k]) && is_string($post[$k])) { return $post[$k]; } } return ''; };
        $v = $this->contentVerdict(['email' => $pick(['your-email', 'email']), 'name' => $pick(['your-name', 'name']), 'subject' => $pick(['your-subject', 'subject']), 'message' => $pick(['your-message', 'message'])]);
        return $v !== 'allow';
    }

    /* ---------- Settings ---------- */

    public function register_settings(): void
    {
        register_setting('empedia_captcha_group', self::OPT, ['sanitize_callback' => [$this, 'sanitize']]);
    }

    public function sanitize($in): array
    {
        $old = self::opts();
        $in = is_array($in) ? $in : [];
        $o = [];
        $base = esc_url_raw(trim((string) ($in['base'] ?? '')));
        $o['base'] = (strpos($base, 'https://') === 0 || preg_match('#^http://(localhost|127\.0\.0\.1)#', $base)) ? rtrim($base, '/') : '';
        $o['sitekey'] = preg_replace('/[^A-Za-z0-9_\-]/', '', (string) ($in['sitekey'] ?? ''));
        $secret = preg_replace('/[^A-Za-z0-9_\-]/', '', (string) ($in['secret'] ?? ''));
        $stored = get_option(self::OPT, []);
        $o['secret'] = $secret !== '' ? $secret : (string) (is_array($stored) ? ($stored['secret'] ?? '') : '');
        $o['fail_open'] = empty($in['fail_open']) ? 0 : 1;
        $o['content_check'] = empty($in['content_check']) ? 0 : 1;
        $o['gate'] = empty($in['gate']) ? 0 : 1;
        $o['forms'] = [];
        foreach (array_keys(self::defaults()['forms']) as $f) { $o['forms'][$f] = empty($in['forms'][$f]) ? 0 : 1; }
        return $o;
    }

    /** Short state for the dashboard widget of EMPEDIAcloud: switched off, configured, protected forms, refused checks. */
    public static function summary(): array
    {
        $o = self::opts();
        $fails = get_option('empedia_captcha_fails', []);
        return [
            'off' => self::off(),
            'configured' => $o['base'] !== '' && $o['sitekey'] !== '' && $o['secret'] !== '',
            'forms' => array_keys(array_filter((array) ($o['forms'] ?? []))),
            'refused' => is_array($fails) ? count($fails) : 0,
        ];
    }

    /** The settings form and the list of refused checks ( also shown inside the tab of EMPEDIAcloud ). */
    public static function render_form(): void
    {
        $o = self::opts();
        $name = self::OPT;
        $labels = ['login' => __('Sign-in', 'empedia-shield'), 'register' => __('Registration', 'empedia-shield'), 'lostpassword' => __('Lost password', 'empedia-shield'),
            'comment' => __('Comments', 'empedia-shield'), 'cf7' => 'Contact Form 7', 'woo' => 'WooCommerce'];
        if (self::off()) { echo '<div class="notice notice-warning inline"><p>' . esc_html__('Bot protection is switched off by EMPEDIA_CAPTCHA_OFF in wp-config.php.', 'empedia-shield') . '</p></div>'; }
        echo '<p class="description">' . esc_html__('Emergency exit if you cannot sign in any more: add define( \'EMPEDIA_CAPTCHA_OFF\', true ); to wp-config.php – or rename the plugin folder.', 'empedia-shield') . '</p><form method="post" action="options.php">';
        settings_fields('empedia_captcha_group');
        echo '<table class="form-table" role="presentation">';
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- $html is built by the callers below, every value is escaped there.
        $row = function ($label, $html, $hint = '') { echo '<tr><th scope="row">' . esc_html($label) . '</th><td>' . $html . ($hint ? '<p class="description">' . wp_kses_post($hint) . '</p>' : '') . '</td></tr>'; };
        $lock = function ($k) use ($o) { return !empty($o['_const_' . $k]) ? ' readonly' : ''; };
        $row(__('Service address', 'empedia-shield'), '<input type="url" class="regular-text" name="' . $name . '[base]" value="' . esc_attr($o['base']) . '" placeholder="https://captcha.example.com"' . $lock('base') . '>');
        $row(__('Site key', 'empedia-shield'), '<input type="text" class="regular-text" name="' . $name . '[sitekey]" value="' . esc_attr($o['sitekey']) . '" placeholder="ek_site_…"' . $lock('sitekey') . '>');
        $secretConst = !empty($o['_const_secret']);
        $row(__('Secret key', 'empedia-shield'), $secretConst ? '<em>' . esc_html__('set in wp-config.php (EMPEDIA_CAPTCHA_SECRET)', 'empedia-shield') . '</em>'
            : '<input type="password" class="regular-text" name="' . $name . '[secret]" value="" autocomplete="new-password" placeholder="' . ($o['secret'] !== '' ? '••••••••' : 'ek_secret_…') . '">',
            __('Better in <code>wp-config.php</code>: <code>define(\'EMPEDIA_CAPTCHA_SECRET\', \'…\');</code> – then it is not stored in the database.', 'empedia-shield'));
        $cb = '';
        foreach ($labels as $k => $l) { $cb .= '<label style="display:block"><input type="checkbox" name="' . $name . '[forms][' . $k . ']" value="1"' . checked(!empty($o['forms'][$k]), true, false) . '> ' . esc_html($l) . '</label>'; }
        $row(__('Protected forms', 'empedia-shield'), $cb);
        $row(__('Content check', 'empedia-shield'), '<label><input type="checkbox" name="' . $name . '[content_check]" value="1"' . checked(!empty($o['content_check']), true, false) . '> ' . esc_html__('Also check the content of comments and Contact Form 7 messages (from the Pro package)', 'empedia-shield') . '</label>');
        $row(__('When the service is unavailable', 'empedia-shield'), '<label><input type="checkbox" name="' . $name . '[fail_open]" value="1"' . checked(!empty($o['fail_open']), true, false) . '> ' . esc_html__('Let requests pass (recommended – otherwise nobody can sign in during an outage)', 'empedia-shield') . '</label>');
        $row(__('Page gate', 'empedia-shield'), '<label><input type="checkbox" name="' . $name . '[gate]" value="1"' . checked(!empty($o['gate']), true, false) . '> ' . esc_html__('Check in front of the whole website (search engines, sign-in and administration stay free)', 'empedia-shield') . '</label>',
            __('The page gate must also be switched on for this domain in the EMPEDIAcaptcha service.', 'empedia-shield'));
        echo '</table>';
        submit_button();
        echo '</form>';
        $fails = get_option('empedia_captcha_fails', []);
        if (is_array($fails) && $fails) {
            $why = [
                'missing-input-response' => __('No check token arrived: the script was not loaded or run in the browser (ad blocker, caching or optimization plugin, content security policy?).', 'empedia-shield'),
                'invalid-input-response' => __('The token was invalid (changed or expired).', 'empedia-shield'),
                'timeout-or-duplicate' => __('The token had expired or was already used (page open for a long time or delivered from a cache).', 'empedia-shield'),
                'action-mismatch' => __('The token comes from a different form.', 'empedia-shield'),
                'invalid-input-secret' => __('The secret key is wrong (after renewing the key in the EMPEDIAcaptcha service, enter the new key here).', 'empedia-shield'),
                'missing-input-secret' => __('No secret key is entered.', 'empedia-shield'),
                'rate-limited' => __('Too many checks from this server in a short time.', 'empedia-shield'),
            ];
            echo '<h2>' . esc_html__('Recently refused checks', 'empedia-shield') . '</h2><table class="widefat striped" style="max-width:900px"><thead><tr><th>' . esc_html__('Time', 'empedia-shield') . '</th><th>' . esc_html__('Form', 'empedia-shield') . '</th><th>' . esc_html__('Reason', 'empedia-shield') . '</th></tr></thead><tbody>';
            foreach ($fails as $f) {
                $code = explode(',', (string) ($f['c'] ?? ''))[0];
                echo '<tr><td>' . esc_html(Empedia_Cloud_Admin::fmt_date((int) ($f['t'] ?? 0))) . '</td><td>' . esc_html((string) ($f['a'] ?? '')) . '</td><td>' . esc_html($why[$code] ?? (string) ($f['c'] ?? '')) . '</td></tr>';
            }
            echo '</tbody></table>';
        }
    }
}

} // class_exists

if (!function_exists('empedia_captcha_gate_boot')) {
/**
 * Page gate: load early, but never for admin, login, cron, REST, Ajax, CLI or signed-in people.
 * Called on plugins_loaded (priority 1) when the module is started.
 */
function empedia_captcha_gate_boot()
{
    if (Empedia_Captcha_Plugin::off()) { return; }
    $o = Empedia_Captcha_Plugin::opts();
    if (empty($o['gate']) || $o['base'] === '' || $o['sitekey'] === '' || $o['secret'] === '') { return; }
    if ((defined('WP_CLI') && WP_CLI) || (defined('DOING_CRON') && DOING_CRON) || (defined('DOING_AJAX') && DOING_AJAX) || (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) || (defined('REST_REQUEST') && REST_REQUEST) || PHP_SAPI === 'cli') { return; }
    $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'])) : '';
    if (preg_match('#/(wp-admin|wp-login\.php|wp-cron\.php|xmlrpc\.php|wp-json)(/|$|\?)#', $uri)) { return; }
    foreach (array_keys($_COOKIE) as $c) { if (strpos((string) $c, 'wordpress_logged_in_') === 0) { return; } }
    Empedia_Captcha_Gate::run(['base' => rtrim($o['base'], '/'), 'sitekey' => $o['sitekey'], 'secret' => $o['secret']]);
}
}
