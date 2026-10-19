# EMPEDIAcaptcha für TYPO3 (Beta)

> Beta: gebaut nach der TYPO3-Dokumentation, **noch nicht an einer TYPO3-Installation geprüft**.

Version 1.0.1: bei erschöpftem Kontingent und `failOpen` werden Anfragen ohne Token durchgelassen (braucht `urbanstudio/empedia-captcha` ≥ 1.0.1).

1. `composer require urbanstudio/empedia-captcha-typo3`
2. Erweiterungskonfiguration: Adresse, Website-Schlüssel; den geheimen Schlüssel als Umgebungsvariable `EMPEDIA_CAPTCHA_SECRET`.
3. Im Fluid-Template: `{namespace ec=Urbanstudio\EmpediaCaptcha\ViewHelpers}` und `<ec:widget action="contact" />` im Formular.
4. Im Controller/Finisher prüfen:
   ```php
   use Urbanstudio\EmpediaCaptcha\Service\CaptchaService;
   if (!CaptchaService::verify($request->getParsedBody()['empedia-captcha-token'] ?? '', 'contact')) { /* ablehnen */ }
   ```
