# EMPEDIAcaptcha & EMPEDIA Shield – SDKs, Plugins, API

Öffentliche Bausteine von [EMPEDIAcloud](https://empedia.cloud) (urbanstudio GmbH). **Dieses Repository ist ein Spiegel** – es wird automatisch aus dem Hauptrepository erzeugt. Fehler und Wünsche gern als Issue; Änderungen pflegen wir im Hauptrepository.

| Ordner | Inhalt | Paket |
|---|---|---|
| `php/` | PHP-SDK | Packagist `urbanstudio/empedia-captcha` |
| `node/` | Node.js-SDK | npm `@urbanstudio/empedia-captcha` |
| `python/` | Python-SDK | PyPI `empedia-captcha` |
| `go/` | Go-SDK | Go-Modul `github.com/urbanstudioGmbH/empedia-captcha/go` |
| `react/` | React-/Next.js-Baustein | npm `@urbanstudio/empedia-captcha-react` |
| `wordpress/empedia-shield/` | WordPress-Plugin „EMPEDIA Shield“ (Sicherheits-Einstellungen, Anmeldeschutz, Dateiprüfung, Firewall, Backups, Bot-Schutz EMPEDIAcaptcha für Login, Registrierung, Kommentare, Contact Form 7, WooCommerce, Seitenschutz) | wordpress.org, ZIP in den Releases |
| `wordpress/empedia-shield-sftp/` | Zusatzplugin „EMPEDIA Shield SFTP“ (SFTP als Backup-Ziel, braucht EMPEDIA Shield) | nicht im Verzeichnis, Auslieferung über EMPEDIAcloud; ZIP zusätzlich in den Releases |
| `typo3/empedia_captcha/` | TYPO3-Erweiterung (Beta) | Packagist `urbanstudio/empedia-captcha-typo3` |
| `shopware/EmpediaCaptcha/` | Shopware-6-Plugin (Beta) | Packagist `urbanstudio/empedia-captcha-shopware` |
| `examples/` | Beispiele: Laravel, Symfony, Vue, Svelte, Server-zu-Server | – |
| `gate/` | Seitenschutz-Module (PHP, Express) | – |
| `api/` | OpenAPI-Beschreibung der EMPEDIAcaptcha-Verwaltungsendpunkte (`openapi.en.json`, `openapi.de.json`) | – |

Anleitung: <https://empedia.cloud/docs-guides/captcha.html> · API-Referenz: <https://empedia.cloud/api-reference.html>

Lizenz: Die SDKs, Beispiele, Gate-Module und das Shopware-Plugin stehen unter MIT. Die TYPO3-Erweiterung und beide WordPress-Plugins stehen unter GPL-2.0-or-later. Das SFTP-Zusatzplugin enthält außerdem phpseclib 3 unter MIT.
