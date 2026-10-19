# empedia-captcha (PHP)

SDK für **EMPEDIAcaptcha** – ohne Abhängigkeiten, PHP ≥ 7.4.

```bash
composer require urbanstudio/empedia-captcha
# oder: sdk/php/src in das eigene Projekt kopieren und Client, VerifyResult, CheckResult und Widget einbinden (HttpTransport.php lädt der Client bei Bedarf selbst)
```

```php
use Empedia\Captcha\{Client, Widget};

$captcha = Client::fromEnv();            // EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE (Umgebungsvariable oder PHP-Konstante)

// Im Formular
echo Widget::script($captcha->base());
echo Widget::element($captcha->sitekey(), 'contact');

// Beim Absenden
$r = $captcha->verify($_POST[Client::TOKEN_FIELD] ?? '', 'contact');
if (!$r->success) { http_response_code(400); exit('Bitte erneut versuchen.'); }

// Optional: Inhaltsprüfung (ab Paket „Pro“)
$v = $captcha->check(['ip' => $_SERVER['REMOTE_ADDR'], 'email' => $email, 'message' => $text]);
if ($v->isBlocked()) { /* ablehnen */ } elseif ($v->needsReview()) { /* in den Spam-Ordner */ }
```

- Das **Secret** gehört nur auf den Server.
- Nicht erreichbarer Dienst: `new Client(..., ['failOpen' => true])` lässt Anfragen durch (Standard: ablehnen). Auch bei erschöpftem Kontingent und `failOpen` werden Anfragen ohne Token durchgelassen (`$captcha->quotaExceeded()`).
- Eigene HTTP-Schicht: `new Client(..., ['transport' => fn ($method, $url, $body, $headers, $timeout) => …])` (Antworttext oder `null`), z. B. `wp_remote_request` in WordPress; ohne Angabe cURL bzw. PHP-Streams.
- Rückmeldung an das System: `$captcha->report('spam'|'ham', ['email' => …, 'ip' => …])`.

## Ohne Browser

`$c->getToken('api', 'https://shop.example.com')` rechnet die Aufgabe selbst (Server-zu-Server). Macht offene Endpunkte für Massenabfragen teuer; prüft keine Menschen. Beispiele für Laravel/Symfony: Ordner `examples`.
