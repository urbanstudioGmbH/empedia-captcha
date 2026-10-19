# empedia-captcha (Python)

SDK für **EMPEDIAcaptcha** – Python ≥ 3.8, nur Standardbibliothek.

```python
from empedia_captcha import EmpediaCaptcha
captcha = EmpediaCaptcha.from_env()   # EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE

r = captcha.verify(request.form.get("empedia-captcha-token"), "contact")
if not r.success:
    abort(400)

v = captcha.check({"ip": ip, "email": email, "message": text})   # Inhaltsprüfung (ab Paket „Pro“)
if v.is_blocked: ...
elif v.needs_review: ...
```

Das **Secret** gehört nur auf den Server. `fail_open=True` lässt Anfragen durch, wenn der Dienst nicht erreichbar ist (Standard: ablehnen). Auch bei erschöpftem Kontingent und `fail_open` werden Anfragen ohne Token durchgelassen (`captcha.quota_exceeded()`).
Widget-HTML: `captcha.script_tag()` einmal je Seite, `captcha.widget_tag("contact")` im Formular.

## Ohne Browser

`captcha.get_token('api', 'https://shop.example.com')` rechnet die Aufgabe selbst (Server-zu-Server). Macht offene Endpunkte für Massenabfragen teuer; prüft keine Menschen.
