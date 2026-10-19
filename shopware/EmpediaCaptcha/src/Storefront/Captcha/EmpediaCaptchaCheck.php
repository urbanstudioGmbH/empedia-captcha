<?php declare(strict_types=1);

namespace Urbanstudio\EmpediaCaptcha\Storefront\Captcha;

use Shopware\Core\System\SystemConfig\SystemConfigService;
use Shopware\Storefront\Framework\Captcha\AbstractCaptcha;
use Symfony\Component\HttpFoundation\Request;

/** Eigene Captcha-Art für die Storefront (Verwaltung → Einstellungen → Shop → Basisinformationen → Captcha). */
class EmpediaCaptchaCheck extends AbstractCaptcha
{
    public const CAPTCHA_NAME = 'empediaCaptcha';
    public const TOKEN_FIELD = 'empedia-captcha-token';

    public function __construct(private readonly SystemConfigService $config)
    {
    }

    public function supports(Request $request, array $captchaConfig): bool
    {
        return parent::supports($request, $captchaConfig) && ($captchaConfig['isActive'] ?? false);
    }

    public function isValid(Request $request, array $captchaConfig): bool
    {
        $base = rtrim((string) $this->config->get('EmpediaCaptcha.config.base'), '/');
        $secret = (string) ($this->config->get('EmpediaCaptcha.config.secret') ?: getenv('EMPEDIA_CAPTCHA_SECRET'));
        if ($base === '' || $secret === '') { return true; } // nicht eingerichtet: nichts blockieren
        $token = (string) $request->request->get(self::TOKEN_FIELD, '');
        if ($token === '') {
            // Ohne Token: ist das Kontingent der Domain erschöpft, bekommt das Widget keine Aufgabe mehr. Wer „Anfragen durchlassen“ gewählt hat, sperrt dann keine Besucher aus.
            return (bool) $this->config->get('EmpediaCaptcha.config.failOpen') && $this->quotaExceeded($base);
        }
        $ctx = stream_context_create(['http' => ['method' => 'POST', 'timeout' => 4, 'ignore_errors' => true,
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n", 'content' => http_build_query(['secret' => $secret, 'response' => $token])]]);
        $res = @file_get_contents($base . '/captcha/v1/siteverify', false, $ctx);
        if ($res === false) { return (bool) $this->config->get('EmpediaCaptcha.config.failOpen'); }
        $j = json_decode($res, true);
        return is_array($j) && ($j['success'] ?? false) === true;
    }

    /** Ist das Kontingent der Domain erschöpft? (Antwort des Dienstes, bei Fehlern false.) */
    private function quotaExceeded(string $base): bool
    {
        $sitekey = (string) $this->config->get('EmpediaCaptcha.config.sitekey');
        if ($sitekey === '') { return false; }
        $ctx = stream_context_create(['http' => ['method' => 'GET', 'timeout' => 4, 'ignore_errors' => true]]);
        $res = @file_get_contents($base . '/captcha/v1/status?sitekey=' . rawurlencode($sitekey), false, $ctx);
        $j = $res === false ? null : json_decode($res, true);
        return is_array($j) && ($j['quota_exceeded'] ?? false) === true;
    }

    public function getName(): string
    {
        return self::CAPTCHA_NAME;
    }
}
