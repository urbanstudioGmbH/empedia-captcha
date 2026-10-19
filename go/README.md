# EMPEDIAcaptcha für Go

```go
c := empedia.FromEnv() // EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE
ok, _ := c.Verify(r.FormValue(empedia.TokenField), "contact")
if !ok { http.Error(w, "Bitte erneut versuchen", http.StatusBadRequest); return }
res := c.Check(map[string]string{"email": email, "message": text}, "") // res.Verdict: allow | review | block
```

Ohne Browser (Server-zu-Server): `token, err := c.GetToken("api", "https://shop.example.com")` rechnet die Aufgabe selbst.
Das Secret gehört nur auf den Server. Mit `c.FailOpen = true` werden Anfragen durchgelassen, wenn der Dienst nicht erreichbar ist oder (ohne Token) das Kontingent erschöpft ist (`c.QuotaExceeded()`).
