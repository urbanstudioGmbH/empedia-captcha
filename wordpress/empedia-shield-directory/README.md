# Verzeichnis-Grafiken für EMPEDIA Shield (wordpress.org)

Diese Dateien gehören **nicht** ins Plugin-ZIP (`dist/empedia-shield.zip`), sondern bei der Einreichung bzw. Veröffentlichung in das SVN-Verzeichnis `assets/` des Plugins (`https://plugins.svn.wordpress.org/empedia-shield/assets/`, neben `trunk/` und `tags/`).

| Datei | Maße | Ziel in SVN `assets/` | Stand |
| --- | --- | --- | --- |
| `icon-128x128.png` | 128 × 128 | `icon-128x128.png` | E-Symbol der Marke (bestehendes Logo, Auftraggeber hat zugestimmt), aus `frontend/img/empedia-icon-1024.png` verkleinert |
| `icon-256x256.png` | 256 × 256 | `icon-256x256.png` | wie oben |
| `screenshots/screenshot-1.png` … `screenshot-8.png` | je 1280 × 800 | `screenshot-1.png` … `screenshot-8.png` | fertig |
| `banner-772x250.png`, `banner-1544x500.png` | 772 × 250 / 1544 × 500 (unter 400 KB) | gleicher Name | **Entwurf aus der Marke – vor der Einreichung ansehen und freigeben**; gleiches Motiv, zweite Datei in doppelter Auflösung |
| `banner-source.html` | – | nicht für wordpress.org | Quelle der Banner (HTML/CSS); gerendert mit `scripts/ops/make-wordpress-banner.mjs` |
| `logo-light.svg`, `logo-dark.svg` | – | nicht für wordpress.org (nur Kopien der Wortmarke) | – |

## Banner und Icons neu erzeugen

`PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers node scripts/ops/make-wordpress-banner.mjs` rendert `banner-source.html` mit Playwright-Chromium (772 × 250 CSS-Pixel, Faktor 1 und 2) und erzeugt auch die beiden Icons neu. Motiv: dunkler Markengrund (`#131B22`/`#1F2830`), E-Symbol, „EMPEDIA Shield“ groß, darunter „Security, Firewall & Backups“, grüner Strich (`#2D8A3A`/`#1D7D43`), schwacher Schild im Hintergrund. Alles Wichtige liegt mittig (WordPress.org beschneidet die Seiten auf kleinen Bildschirmen); keine Fremdmarken, keine WordPress-Logos. Anderen Text oder andere Farben: nur `banner-source.html` ändern und das Skript neu laufen lassen.

## Screenshots

Die Nummern entsprechen den Zeilen `1.` bis `8.` im Abschnitt `== Screenshots ==` der `readme.txt`; die Reihenfolge dort und hier muss übereinstimmen.

1. Übersicht (Reiter „Overview“)
2. Sicherheits-Einstellungen mit „Secure now“ (Teil angewendet, Teil offen)
3. Anmeldeschutz: zweiter Faktor, Passkeys, Pflicht je Rolle
4. Dateiprüfung nach einem Lauf
5. Firewall im Beobachten-Modus
6. Backups (ein gespeichertes Backup, Ziele, Einstellungen)
7. Bot-Schutz (EMPEDIAcaptcha)
8. Kommentare

Entstanden in einer lokalen Test-WordPress-Instanz (WordPress 7.1.3, en_US, Testbenutzer `admin`, Beispielseite „Example Site“), **ohne Cloud-Verbindung**, nur mit lokalen Funktionen. Deshalb zeigt die Übersicht die Verbindungskarte und nicht die Cloud-Bewertung (Schutz-Note, Schwachstellen); sobald die Cloud-Ansichten als Screenshot gewünscht sind, mit einer verbundenen Testseite neu aufnehmen. Der Sicherungsschlüssel auf dem Backups-Bild ist unkenntlich gemacht (Testschlüssel).

Neu aufnehmen: Viewport 1280 × 800, PNG, ohne Browserleiste, mit Playwright (Chromium) gegen die Testinstanz; Seiten wie oben (`admin.php?page=empedia-cloud&tab=login|files|firewall|bots|comments|backups`). Empfehlung von wordpress.org: Breite höchstens 1280 px (größere werden verkleinert).
