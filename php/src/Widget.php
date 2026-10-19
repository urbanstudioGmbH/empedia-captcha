<?php
declare(strict_types=1);

namespace Empedia\Captcha;

/** HTML-Helfer für das Widget: einmal `script()` je Seite, `element()` im Formular. */
final class Widget
{
    public static function script(string $base): string
    {
        return '<script src="' . htmlspecialchars(rtrim($base, '/'), ENT_QUOTES) . '/captcha/v1/widget.js" async defer></script>';
    }

    /** $options: mode (focus|load|submit), badge (bool) */
    public static function element(string $sitekey, string $action = 'form', array $options = []): string
    {
        $a = ' data-sitekey="' . htmlspecialchars($sitekey, ENT_QUOTES) . '" data-action="' . htmlspecialchars($action, ENT_QUOTES) . '"';
        if (isset($options['mode'])) { $a .= ' data-mode="' . htmlspecialchars((string) $options['mode'], ENT_QUOTES) . '"'; }
        if (isset($options['badge']) && $options['badge'] === false) { $a .= ' data-badge="false"'; }
        return '<div class="empedia-captcha"' . $a . '></div>';
    }
}
