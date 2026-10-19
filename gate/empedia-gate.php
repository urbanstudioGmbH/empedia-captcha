<?php
/**
 * EMPEDIAcaptcha – Seitenschutz (Vorschaltprüfung) für PHP-Websites.
 *
 * Besucher ohne gültigen Durchlass werden kurz auf die Prüfseite des Captcha-Dienstes geleitet und kommen danach zurück;
 * dieses Modul prüft das Token (siteverify) und setzt einen eigenen, signierten Cookie („empedia_pass“, technisch notwendig).
 *
 * Einbinden (eine Möglichkeit genügt):
 *   - php.ini / .user.ini:   auto_prepend_file = "/pfad/zu/empedia-gate.php"
 *   - ganz oben in index.php: require __DIR__ . '/empedia-gate.php';
 *
 * Einstellungen (Umgebungsvariable oder PHP-Konstante gleichen Namens, z. B. in wp-config.php):
 *   EMPEDIA_CAPTCHA_SITEKEY   Site-Key (ek_site_…)
 *   EMPEDIA_CAPTCHA_SECRET    Secret – nur auf dem Server, nie im Browser oder Repository
 *   EMPEDIA_CAPTCHA_BASE      Adresse des Dienstes, z. B. https://captcha.example.com
 *   EMPEDIA_TRUST_PROXY       „1“, wenn ein Reverse-Proxy X-Forwarded-Proto/-For zuverlässig setzt (optional)
 *
 * Ein- und Ausschalten, Gültigkeit und Ausnahmen stellen Sie in der Oberfläche unter „Seitenschutz“ ein; das Modul liest sie alle 60 Sekunden.
 * Ist der Dienst nicht erreichbar, lässt das Modul alle Besucher durch (die Website bleibt erreichbar).
 */
if (!function_exists('empedia_gate_run')) {

function empedia_gate_env(string $k): string {
    if (defined($k)) { return (string) constant($k); }
    $v = getenv($k);
    return $v === false ? '' : (string) $v;
}

function empedia_gate_http(string $url, ?array $post = null): ?string {
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        $o = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 4, CURLOPT_CONNECTTIMEOUT => 2];
        if ($post !== null) { $o[CURLOPT_POST] = true; $o[CURLOPT_POSTFIELDS] = http_build_query($post); }
        curl_setopt_array($ch, $o);
        $out = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        return ($out !== false && $code >= 200 && $code < 300) ? $out : null;
    }
    $ctx = stream_context_create(['http' => ['timeout' => 4, 'method' => $post !== null ? 'POST' : 'GET',
        'header' => $post !== null ? "Content-Type: application/x-www-form-urlencoded\r\n" : '', 'content' => $post !== null ? http_build_query($post) : '', 'ignore_errors' => false]]);
    $out = @file_get_contents($url, false, $ctx);
    return $out === false ? null : $out;
}

function empedia_gate_config(string $base, string $sitekey): ?array {
    $f = sys_get_temp_dir() . '/empedia_gate_' . md5($base . $sitekey) . '.json';
    $age = @filemtime($f);
    if ($age && time() - $age < 60) { $c = json_decode((string) @file_get_contents($f), true); if (is_array($c)) return $c; }
    $raw = empedia_gate_http($base . '/captcha/v1/gate-config?sitekey=' . rawurlencode($sitekey));
    $c = $raw !== null ? json_decode($raw, true) : null;
    if (is_array($c) && array_key_exists('enabled', $c)) { @file_put_contents($f, $raw, LOCK_EX); return $c; }
    $old = json_decode((string) @file_get_contents($f), true); // Dienst nicht erreichbar: letzte bekannte Einstellung weiter nutzen
    return is_array($old) ? $old : null;
}

function empedia_gate_b64(string $bin): string { return rtrim(strtr(base64_encode($bin), '+/', '-_'), '='); }
function empedia_gate_ua(): string { return substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 200); }
function empedia_gate_sig(int $exp, string $secret): string { return empedia_gate_b64(hash_hmac('sha256', $exp . '|' . empedia_gate_ua(), $secret, true)); }

function empedia_gate_cookie_ok(string $secret): bool {
    $v = $_COOKIE['empedia_pass'] ?? '';
    if (!is_string($v) || !preg_match('/^(\d{9,11})\.([A-Za-z0-9_-]{43})$/', $v, $m)) return false;
    return (int) $m[1] > time() && hash_equals(empedia_gate_sig((int) $m[1], $secret), $m[2]);
}

function empedia_gate_https(): bool {
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') return true;
    return empedia_gate_env('EMPEDIA_TRUST_PROXY') === '1' && strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}
function empedia_gate_host(): string { return (string) ($_SERVER['HTTP_HOST'] ?? ''); }
function empedia_gate_url(bool $withoutGate = false): string {
    $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
    if ($withoutGate) {
        $parts = explode('?', $uri, 2);
        $qs = isset($parts[1]) ? preg_replace('/(^|&)empedia_gate=[^&]*/', '', $parts[1]) : '';
        $qs = ltrim((string) $qs, '&');
        $uri = $parts[0] . ($qs !== '' ? '?' . $qs : '');
    }
    return (empedia_gate_https() ? 'https' : 'http') . '://' . empedia_gate_host() . $uri;
}

function empedia_gate_client_ip(): string {
    if (empedia_gate_env('EMPEDIA_TRUST_PROXY') === '1' && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) { return trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_FOR'])[0]); }
    return (string) ($_SERVER['REMOTE_ADDR'] ?? '');
}

/** Suchmaschinen-Robot: umgekehrte DNS-Auflösung muss auf eine bekannte Domain zeigen und vorwärts zur selben Adresse führen (Ergebnis 1 Tag gemerkt). */
function empedia_gate_is_crawler(array $cfg): bool {
    $ip = empedia_gate_client_ip();
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) return false;
    $f = sys_get_temp_dir() . '/empedia_gate_bot_' . md5($ip);
    $age = @filemtime($f);
    if ($age && time() - $age < 86400) return @file_get_contents($f) === '1';
    $ok = false;
    $host = strtolower((string) @gethostbyaddr($ip));
    if ($host !== '' && $host !== strtolower($ip)) {
        foreach ((array) ($cfg['crawler_suffixes'] ?? []) as $suf) {
            if ($suf !== '' && substr($host, -strlen($suf)) === $suf) {
                $fwd = filter_var($ip, FILTER_FLAG_IPV6) !== false && strpos($ip, ':') !== false
                    ? array_column((array) @dns_get_record($host, DNS_AAAA), 'ipv6') : (array) @gethostbynamel($host);
                $ok = in_array($ip, $fwd, true);
                break;
            }
        }
    }
    @file_put_contents($f, $ok ? '1' : '0');
    return $ok;
}

function empedia_gate_deny(string $text): void {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo $text;
    exit;
}

function empedia_gate_run(): void {
    if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg') return;
    $secret = empedia_gate_env('EMPEDIA_CAPTCHA_SECRET'); $sitekey = empedia_gate_env('EMPEDIA_CAPTCHA_SITEKEY'); $base = rtrim(empedia_gate_env('EMPEDIA_CAPTCHA_BASE'), '/');
    if ($secret === '' || $sitekey === '' || $base === '') return;
    $cfg = empedia_gate_config($base, $sitekey);
    if (!$cfg || empty($cfg['enabled'])) return;

    $method = (string) ($_SERVER['REQUEST_METHOD'] ?? 'GET');
    $path = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH) ?: '/';
    foreach ((array) ($cfg['skip'] ?? []) as $p) { if ($p !== '' && strpos($path, (string) $p) === 0) return; }

    // Rückkehr von der Prüfseite: Token prüfen, Durchlass ausstellen
    if (isset($_GET['empedia_gate']) && is_string($_GET['empedia_gate'])) {
        $raw = empedia_gate_http($base . '/captcha/v1/siteverify', ['secret' => $secret, 'response' => $_GET['empedia_gate'], 'action' => 'gate']);
        $r = $raw !== null ? json_decode($raw, true) : null;
        $host = strtolower((string) preg_replace('/:\d+$/', '', empedia_gate_host()));
        if (is_array($r) && ($r['success'] ?? false) === true && strtolower((string) ($r['hostname'] ?? '')) === $host) {
            $exp = time() + max(5, (int) ($cfg['ttl_min'] ?? 60)) * 60;
            setcookie('empedia_pass', $exp . '.' . empedia_gate_sig($exp, $secret), ['expires' => $exp, 'path' => '/', 'secure' => empedia_gate_https(), 'httponly' => true, 'samesite' => 'Lax']);
            header('Cache-Control: no-store');
            header('Location: ' . empedia_gate_url(true), true, 302);
            exit;
        }
        empedia_gate_deny('Verification failed.'); // keine erneute Weiterleitung: verhindert Schleifen
    }

    if (empedia_gate_cookie_ok($secret)) return;
    if (!empty($cfg['crawlers']) && empedia_gate_is_crawler($cfg)) return;

    $wantsHtml = in_array($method, ['GET', 'HEAD'], true) && stripos((string) ($_SERVER['HTTP_ACCEPT'] ?? ''), 'text/html') !== false;
    if ($wantsHtml) {
        header('Cache-Control: no-store');
        header('Location: ' . $base . '/captcha/v1/gate?sitekey=' . rawurlencode($sitekey) . '&return=' . rawurlencode(empedia_gate_url()), true, 302);
        exit;
    }
    empedia_gate_deny('Forbidden.'); // Skripte, Formular-Abschicken und Hintergrundaufrufe ohne Durchlass
}

empedia_gate_run();
}
