// Package empedia ist das SDK für EMPEDIAcaptcha (ohne Abhängigkeiten).
//
//	c := empedia.New(sitekey, secret, "https://captcha.example.com")
//	ok, _ := c.Verify(r.FormValue(empedia.TokenField), "contact")
//
// Das Secret gehört nur auf den Server. Ist der Dienst nicht erreichbar, entscheidet FailOpen (Standard false = ablehnen).
package empedia

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// TokenField ist der Name des versteckten Formularfelds, das das Widget befüllt.
const TokenField = "empedia-captcha-token"

// Client spricht mit dem EMPEDIAcaptcha-Dienst.
type Client struct {
	Sitekey, Secret, Base string
	FailOpen              bool
	HTTP                  *http.Client
}

// New legt einen Client an (Timeout 5 s).
func New(sitekey, secret, base string) *Client {
	return &Client{Sitekey: sitekey, Secret: secret, Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 5 * time.Second}}
}

// FromEnv liest EMPEDIA_CAPTCHA_SITEKEY, _SECRET und _BASE.
func FromEnv() *Client {
	return New(os.Getenv("EMPEDIA_CAPTCHA_SITEKEY"), os.Getenv("EMPEDIA_CAPTCHA_SECRET"), os.Getenv("EMPEDIA_CAPTCHA_BASE"))
}

// CheckResult ist das Ergebnis der Inhaltsprüfung: Verdict = allow | review | block.
type CheckResult struct {
	Verdict     string
	Risk        int
	Reasons     []string
	Unreachable bool
}

func (c *Client) post(path string, body any, form bool, origin string, timeout time.Duration) (map[string]any, error) {
	var buf []byte
	ct := "application/json"
	if form {
		v := url.Values{}
		for k, val := range body.(map[string]string) {
			v.Set(k, val)
		}
		buf = []byte(v.Encode())
		ct = "application/x-www-form-urlencoded"
	} else {
		var err error
		if buf, err = json.Marshal(body); err != nil {
			return nil, err
		}
	}
	req, err := http.NewRequest(http.MethodPost, c.Base+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", ct)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	hc := *c.HTTP
	if timeout > 0 {
		hc.Timeout = timeout
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// Verify prüft ein Token der Bot-Prüfung (einmalig verwendbar). Der zweite Rückgabewert ist true, wenn der Dienst nicht erreichbar war.
func (c *Client) Verify(token, action string) (ok bool, unreachable bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		// Ohne Token: ist das Kontingent der Domain erschöpft, bekommt das Widget keine Aufgabe mehr.
		// Wer FailOpen gewählt hat, sperrt dann keine Besucher aus (zweiter Rückgabewert true wie bei „Dienst nicht erreichbar“).
		if c.FailOpen && c.QuotaExceeded() {
			return true, true
		}
		return false, false
	}
	body := map[string]string{"secret": c.Secret, "response": token}
	if action != "" {
		body["action"] = action
	}
	r, err := c.post("/captcha/v1/siteverify", body, true, "", 0)
	if err != nil {
		return c.FailOpen, true
	}
	s, _ := r["success"].(bool)
	return s, false
}

// QuotaExceeded fragt den Dienst, ob das Kontingent dieser Domain erschöpft ist (bei Fehlern false).
func (c *Client) QuotaExceeded() bool {
	resp, err := c.HTTP.Get(c.Base + "/captcha/v1/status?sitekey=" + url.QueryEscape(c.Sitekey))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false
	}
	return out["quota_exceeded"] == true
}

// Check bewertet die Daten einer Anfrage (ip, email, name, username, subject, message, honeypot).
func (c *Client) Check(fields map[string]string, token string) CheckResult {
	body := map[string]any{"sitekey": c.Sitekey, "secret": c.Secret, "fields": fields}
	if token != "" {
		body["response"] = token
	}
	r, err := c.post("/captcha/v1/check", body, false, "", 0)
	if err != nil || r["success"] != true {
		v := "review"
		if c.FailOpen {
			v = "allow"
		}
		return CheckResult{Verdict: v, Reasons: []string{"service-unreachable"}, Unreachable: true}
	}
	res := CheckResult{Verdict: fmt.Sprint(r["verdict"])}
	if f, ok := r["risk"].(float64); ok {
		res.Risk = int(f)
	}
	if rs, ok := r["reasons"].([]any); ok {
		for _, x := range rs {
			res.Reasons = append(res.Reasons, fmt.Sprint(x))
		}
	}
	return res
}

// Report meldet eine Anfrage als "spam" oder "ham" (das System lernt E-Mail und IP als eigene Regel).
func (c *Client) Report(kind string, fields map[string]string) bool {
	r, err := c.post("/captcha/v1/report", map[string]any{"sitekey": c.Sitekey, "secret": c.Secret, "kind": kind, "fields": fields}, false, "", 0)
	return err == nil && r["success"] == true
}

// SolvePow findet die kleinste Zahl n, sodass SHA-256("id:n") mit mindestens bits Nullbits beginnt.
func SolvePow(id string, nbits int, limit int) (int, error) {
	if limit <= 0 {
		limit = 200_000_000
	}
	for n := 0; n < limit; n++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", id, n)))
		z := 0
		for _, b := range h {
			if b == 0 {
				z += 8
				continue
			}
			z += bits.LeadingZeros8(b)
			break
		}
		if z >= nbits {
			return n, nil
		}
	}
	return 0, errors.New("pow-limit")
}

// GetToken beschafft selbst ein Token (Server-zu-Server, ohne Browser). origin muss zu den Hosts der Domain passen
// (z. B. "https://shop.example.com"). Gedacht, um offene Endpunkte teuer zu machen, nicht um Menschen zu prüfen.
func (c *Client) GetToken(action, origin string) (string, error) {
	ch, err := c.post("/captcha/v1/challenge", map[string]any{"sitekey": c.Sitekey, "action": action}, false, origin, 30*time.Second)
	if err != nil {
		return "", err
	}
	chal, ok := ch["challenge"].(map[string]any)
	if !ok {
		return "", errors.New("keine Aufgabe erhalten")
	}
	nonce, err := SolvePow(fmt.Sprint(chal["id"]), int(chal["bits"].(float64)), 0)
	if err != nil {
		return "", err
	}
	r, err := c.post("/captcha/v1/solve", map[string]any{"challenge": chal, "nonce": fmt.Sprint(nonce), "signals": map[string]any{"hp": "", "t": 2500, "wd": false, "hl": false, "ia": 0}}, false, origin, 30*time.Second)
	if err != nil {
		return "", err
	}
	t, _ := r["token"].(string)
	if t == "" {
		return "", errors.New("abgelehnt")
	}
	return t, nil
}
