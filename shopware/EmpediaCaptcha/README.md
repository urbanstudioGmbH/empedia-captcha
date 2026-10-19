# EMPEDIAcaptcha für Shopware 6 (Beta)

> Beta: gebaut nach der Shopware-Dokumentation (Storefront-Captcha, Tag `shopware.storefront.captcha`), **noch nicht an einem Shopware-Shop geprüft**.

1. Ordner nach `custom/plugins/EmpediaCaptcha` kopieren, `bin/console plugin:refresh && plugin:install --activate EmpediaCaptcha`.
2. Plugin-Einstellungen: Adresse, Website-Schlüssel (geheimer Schlüssel besser als Umgebungsvariable `EMPEDIA_CAPTCHA_SECRET`).
3. Verwaltung → Einstellungen → Shop → Basisinformationen → Captcha: „empediaCaptcha“ aktivieren.

Version 1.0.1: Bei erschöpftem Kontingent und aktivem „Bei Ausfall des Dienstes durchlassen“ werden Anfragen ohne Token durchgelassen.
