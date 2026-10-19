# @urbanstudio/empedia-captcha (Node.js)

SDK für **EMPEDIAcaptcha** – Node ≥ 18, ohne Abhängigkeiten.

```js
import { EmpediaCaptcha } from '@urbanstudio/empedia-captcha';
const captcha = EmpediaCaptcha.fromEnv();   // EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE

// Express: prüft das Token (Feld "empedia-captcha-token" oder Header X-Captcha-Token)
app.post('/kontakt', captcha.middleware({ action: 'contact' }), handler);

// oder manuell
const r = await captcha.verify(req.body['empedia-captcha-token'], 'contact');
if (!r.success) return res.status(400).end();

// Inhaltsprüfung (ab Paket „Pro“)
const v = await captcha.check({ ip: req.ip, email, message });
if (v.verdict === 'block') { /* ablehnen */ } else if (v.verdict === 'review') { /* Spam-Ordner */ }
```

Widget-HTML: `captcha.scriptTag()` einmal je Seite, `captcha.widgetTag('contact')` im Formular.
Das **Secret** gehört nur auf den Server. `failOpen: true` lässt Anfragen durch, wenn der Dienst nicht erreichbar ist (Standard: ablehnen). Auch bei erschöpftem Kontingent und `failOpen` werden Anfragen ohne Token durchgelassen (`captcha.quotaExceeded()`).

## Ohne Browser

`await captcha.getToken('api', { origin: 'https://shop.example.com' })` rechnet die Aufgabe selbst (Server-zu-Server). Macht offene Endpunkte für Massenabfragen teuer; prüft keine Menschen.
