<?php
declare(strict_types=1);

namespace Empedia\Captcha;

/**
 * EMPEDIAcaptcha-Client (ohne Abhängigkeiten; HTTP über cURL oder PHP-Streams, austauschbar über die Option `transport`).
 *
 *   $c = Client::fromEnv();                      // EMPEDIA_CAPTCHA_SITEKEY, EMPEDIA_CAPTCHA_SECRET, EMPEDIA_CAPTCHA_BASE
 *   $r = $c->verify($_POST['empedia-captcha-token'] ?? '', 'contact');
 *   if (!$r->success) { http_response_code(400); exit('Bitte erneut versuchen.'); }
 *   $v = $c->check(['ip' => $ip, 'email' => $email, 'message' => $text]);   // Inhaltsprüfung (ab Paket „Pro“)
 *   if ($v->verdict === 'block') { … }  // 'review' → z. B. in den Spam-Ordner
 *
 * Optionen: timeout (Sekunden), failOpen, transport = function (string $method, string $url, ?string $body, array $headers, float $timeout): ?string
 * (Antworttext oder null bei Verbindungsfehler; ohne Angabe HttpTransport mit cURL bzw. PHP-Streams – Plattformen mit eigener HTTP-API
 * wie WordPress reichen ihren Transport hier durch).
 *
 * Das Secret gehört nur auf den Server (Umgebungsvariable oder Konstante), nie in Browser oder Repository.
 * Ist der Dienst nicht erreichbar, entscheidet `failOpen` (Standard: false = ablehnen; true = durchlassen).
 */
final class Client
{
    public const TOKEN_FIELD = 'empedia-captcha-token';

    private string $sitekey;
    private string $secret;
    private string $base;
    private float $timeout;
    private bool $failOpen;
    /** @var callable|null */
    private $transport;

    public function __construct(string $sitekey, string $secret, string $base, array $options = [])
    {
        $this->sitekey = $sitekey;
        $this->secret = $secret;
        $this->base = rtrim($base, '/');
        $this->timeout = (float) ($options['timeout'] ?? 5.0);
        $this->failOpen = (bool) ($options['failOpen'] ?? false);
        $this->transport = isset($options['transport']) && is_callable($options['transport']) ? $options['transport'] : null;
    }

    public static function fromEnv(array $options = []): self
    {
        $get = static function (string $k): string {
            if (defined($k)) { return (string) constant($k); }
            $v = getenv($k);
            return $v === false ? '' : (string) $v;
        };
        return new self($get('EMPEDIA_CAPTCHA_SITEKEY'), $get('EMPEDIA_CAPTCHA_SECRET'), $get('EMPEDIA_CAPTCHA_BASE'), $options);
    }

    public function sitekey(): string { return $this->sitekey; }
    public function base(): string { return $this->base; }

    /** Token der Bot-Prüfung prüfen (einmalig verwendbar). */
    public function verify(?string $token, ?string $action = null): VerifyResult
    {
        $token = trim((string) $token);
        if ($token === '') {
            // Ohne Token: ist das Kontingent der Domain erschöpft, bekommt das Widget keine Aufgabe mehr. Wer „Anfragen durchlassen“ gewählt hat, sperrt dann keine Besucher aus.
            if ($this->failOpen && $this->quotaExceeded()) { return new VerifyResult(true, ['quota-exceeded'], [], true); }
            return new VerifyResult(false, ['missing-input-response']);
        }
        $body = ['secret' => $this->secret, 'response' => $token];
        if ($action !== null && $action !== '') { $body['action'] = $action; }
        $r = $this->post('/captcha/v1/siteverify', $body);
        if ($r === null) { return new VerifyResult($this->failOpen, ['service-unreachable'], [], true); }
        return new VerifyResult(($r['success'] ?? false) === true, (array) ($r['error-codes'] ?? []), $r);
    }

    /** Ist das Kontingent dieser Domain erschöpft? (Antwort des Dienstes, bei Fehlern false.) */
    public function quotaExceeded(): bool
    {
        $url = $this->base . '/captcha/v1/status?sitekey=' . rawurlencode($this->sitekey);
        $out = $this->request('GET', $url, null, [], $this->timeout);
        $j = $out === null ? null : json_decode($out, true);
        return is_array($j) && ($j['quota_exceeded'] ?? false) === true;
    }

    /** Daten einer Anfrage bewerten (ip, email, name, username, subject, message, honeypot); optional `response` = Token derselben Anfrage. */
    public function check(array $fields, ?string $token = null): CheckResult
    {
        $payload = ['sitekey' => $this->sitekey, 'secret' => $this->secret, 'fields' => $fields];
        if ($token !== null && $token !== '') { $payload['response'] = $token; }
        $r = $this->post('/captcha/v1/check', $payload, true);
        if ($r === null || ($r['success'] ?? false) !== true) {
            return new CheckResult($this->failOpen ? 'allow' : 'review', 0, ['service-unreachable'], true);
        }
        return new CheckResult((string) ($r['verdict'] ?? 'allow'), (int) ($r['risk'] ?? 0), (array) ($r['reasons'] ?? []), false, $r);
    }

    /** Rückmeldung: $kind = 'spam' oder 'ham' (war echt) – das System lernt daraus E-Mail und IP als eigene Regel. */
    public function report(string $kind, array $fields): bool
    {
        $r = $this->post('/captcha/v1/report', ['sitekey' => $this->sitekey, 'secret' => $this->secret, 'kind' => $kind, 'fields' => $fields], true);
        return $r !== null && ($r['success'] ?? false) === true;
    }

    /** Proof-of-Work lösen: kleinste Zahl n, sodass SHA-256(id:n) mit $bits Nullbits beginnt. */
    public static function solvePow(string $id, int $bits, int $limit = 200000000): int
    {
        $fullBytes = intdiv($bits, 8); $rest = $bits % 8;
        for ($n = 0; $n < $limit; $n++) {
            $h = hash('sha256', $id . ':' . $n, true);
            $ok = true;
            for ($i = 0; $i < $fullBytes; $i++) { if ($h[$i] !== "\0") { $ok = false; break; } }
            if ($ok && ($rest === 0 || (ord($h[$fullBytes]) >> (8 - $rest)) === 0)) { return $n; }
        }
        throw new \RuntimeException('pow-limit');
    }

    /**
     * Token selbst beschaffen (Server-zu-Server, Skripte, mobile Backends) – ohne Browser. $origin muss zu den Hosts der Domain passen
     * (z. B. 'https://shop.example.com'). Gedacht, um offene Endpunkte teuer zu machen, nicht um Menschen zu prüfen. → Token oder null.
     */
    public function getToken(string $action, string $origin = '', array $signals = []): ?string
    {
        $ch = $this->post('/captcha/v1/challenge', ['sitekey' => $this->sitekey, 'action' => $action], true, $origin);
        if (!is_array($ch) || !isset($ch['challenge']['id'], $ch['challenge']['bits'])) { return null; }
        $nonce = self::solvePow((string) $ch['challenge']['id'], (int) $ch['challenge']['bits']);
        $r = $this->post('/captcha/v1/solve', ['challenge' => $ch['challenge'], 'nonce' => (string) $nonce, 'signals' => $signals + ['hp' => '', 't' => 2500, 'wd' => false, 'hl' => false, 'ia' => 0]], true, $origin);
        return is_array($r) && isset($r['token']) ? (string) $r['token'] : null;
    }

    private function post(string $path, array $data, bool $json = false, string $origin = ''): ?array
    {
        $url = $this->base . $path;
        $body = $json ? json_encode($data) : http_build_query($data);
        $headers = $json ? 'Content-Type: application/json' : 'Content-Type: application/x-www-form-urlencoded';
        $extra = $origin !== '' ? ['Origin: ' . $origin] : [];
        $out = $this->request('POST', $url, $body, array_merge([$headers], $extra), $this->timeout * ($origin !== '' ? 6 : 1));
        if ($out === null) { return null; }
        $j = json_decode($out, true);
        return is_array($j) ? $j : null;
    }

    private function request(string $method, string $url, ?string $body, array $headers, float $timeout): ?string
    {
        if ($this->transport !== null) {
            $out = ($this->transport)($method, $url, $body, $headers, $timeout);
            return $out === null ? null : (string) $out;
        }
        if (!class_exists(HttpTransport::class, false)) { require_once __DIR__ . '/HttpTransport.php'; }
        return HttpTransport::send($method, $url, $body, $headers, $timeout);
    }
}
