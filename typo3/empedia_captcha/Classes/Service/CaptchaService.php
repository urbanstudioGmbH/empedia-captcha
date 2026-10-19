<?php
declare(strict_types=1);

namespace Urbanstudio\EmpediaCaptcha\Service;

use Empedia\Captcha\Client;
use TYPO3\CMS\Core\Configuration\ExtensionConfiguration;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/** Prüft Token und Inhalte; Einstellungen aus der Erweiterungskonfiguration, das Secret bevorzugt aus der Umgebung. */
final class CaptchaService
{
    public static function config(): array
    {
        $c = GeneralUtility::makeInstance(ExtensionConfiguration::class)->get('empedia_captcha');
        $secret = getenv('EMPEDIA_CAPTCHA_SECRET') ?: (string) ($c['secret'] ?? '');
        return ['base' => (string) ($c['base'] ?? ''), 'sitekey' => (string) ($c['sitekey'] ?? ''), 'secret' => $secret, 'failOpen' => !empty($c['failOpen'])];
    }

    public static function client(): Client
    {
        $c = self::config();
        return new Client($c['sitekey'], $c['secret'], $c['base'], ['failOpen' => $c['failOpen']]);
    }

    public static function verify(?string $token, string $action = 'form'): bool
    {
        $c = self::config();
        if ($c['base'] === '' || $c['sitekey'] === '' || $c['secret'] === '') { return true; } // nicht eingerichtet: nichts blockieren
        return self::client()->verify($token, $action)->success;
    }
}
