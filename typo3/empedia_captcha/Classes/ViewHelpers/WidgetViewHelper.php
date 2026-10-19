<?php
declare(strict_types=1);

namespace Urbanstudio\EmpediaCaptcha\ViewHelpers;

use Empedia\Captcha\Widget;
use TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper;
use Urbanstudio\EmpediaCaptcha\Service\CaptchaService;

/** <ec:widget action="contact" /> – einmal Skript, Element im Formular; das Token landet im Feld empedia-captcha-token. */
final class WidgetViewHelper extends AbstractViewHelper
{
    protected $escapeOutput = false;

    public function initializeArguments(): void
    {
        $this->registerArgument('action', 'string', 'Aktion (z. B. contact, login)', false, 'form');
        $this->registerArgument('mode', 'string', 'focus | load | submit', false, 'focus');
    }

    public function render(): string
    {
        $c = CaptchaService::config();
        if ($c['base'] === '' || $c['sitekey'] === '') { return ''; }
        return Widget::script($c['base']) . Widget::element($c['sitekey'], (string) $this->arguments['action'], ['mode' => (string) $this->arguments['mode']]);
    }
}
