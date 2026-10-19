// EMPEDIAcaptcha-SDK für Node.js (≥ 18, ohne Abhängigkeiten).
//   const captcha = EmpediaCaptcha.fromEnv();      // EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE
//   const r = await captcha.verify(req.body['empedia-captcha-token'], 'contact');
//   const v = await captcha.check({ ip, email, message });   // Inhaltsprüfung (ab Paket „Pro“)
// Das Secret gehört nur auf den Server. Dienst nicht erreichbar: `failOpen` entscheidet (Standard false = ablehnen).

import { createHash } from 'node:crypto';

export const TOKEN_FIELD = 'empedia-captcha-token';

const zeroBits = (d) => { let n = 0; for (const x of d) { if (x === 0) { n += 8; continue; } n += Math.clz32(x) - 24; break; } return n; };
/** Proof-of-Work lösen: kleinste Zahl n, sodass SHA-256(id + ":" + n) mit `bits` Nullbits beginnt. */
export function solvePow(id, bits, limit = 200_000_000) { for (let n = 0; n < limit; n++) if (zeroBits(createHash('sha256').update(`${id}:${n}`).digest()) >= bits) return n; throw new Error('pow-limit'); }

export class EmpediaCaptcha {
  constructor({ sitekey, secret, base, timeoutMs = 5000, failOpen = false, fetch: f = globalThis.fetch } = {}) {
    this.sitekey = sitekey ?? ''; this.secret = secret ?? ''; this.base = String(base ?? '').replace(/\/+$/, '');
    this.timeoutMs = timeoutMs; this.failOpen = !!failOpen; this._fetch = f;
  }
  static fromEnv(options = {}, env = process.env) {
    return new EmpediaCaptcha({ sitekey: env.EMPEDIA_CAPTCHA_SITEKEY, secret: env.EMPEDIA_CAPTCHA_SECRET, base: env.EMPEDIA_CAPTCHA_BASE, ...options });
  }

  async _post(path, body) {
    try {
      const r = await this._fetch(this.base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs) });
      const j = await r.json().catch(() => null);
      return j && typeof j === 'object' ? j : null;
    } catch { return null; }
  }

  /** Token der Bot-Prüfung prüfen (einmalig verwendbar). → { success, errorCodes, unreachable, raw } */
  async verify(token, action) {
    token = String(token ?? '').trim();
    if (!token) {
      // Ohne Token: ist das Kontingent der Domain erschöpft, bekommt das Widget keine Aufgabe mehr. Wer „Anfragen durchlassen“ gewählt hat, sperrt dann keine Besucher aus.
      if (this.failOpen && await this.quotaExceeded()) return { success: true, errorCodes: ['quota-exceeded'], unreachable: true, raw: {} };
      return { success: false, errorCodes: ['missing-input-response'], unreachable: false, raw: {} };
    }
    const r = await this._post('/captcha/v1/siteverify', { secret: this.secret, response: token, ...(action ? { action } : {}) });
    if (!r) return { success: this.failOpen, errorCodes: ['service-unreachable'], unreachable: true, raw: {} };
    return { success: r.success === true, errorCodes: r['error-codes'] ?? [], unreachable: false, raw: r };
  }

  /** Ist das Kontingent dieser Domain erschöpft? (Antwort des Dienstes, bei Fehlern false.) */
  async quotaExceeded() {
    try {
      const r = await this._fetch(`${this.base}/captcha/v1/status?sitekey=${encodeURIComponent(this.sitekey)}`, { signal: AbortSignal.timeout(this.timeoutMs) });
      const j = await r.json().catch(() => null);
      return j?.quota_exceeded === true;
    } catch { return false; }
  }

  /** Daten einer Anfrage bewerten → { verdict: 'allow'|'review'|'block', risk, reasons, unreachable, raw } */
  async check(fields, token) {
    const r = await this._post('/captcha/v1/check', { sitekey: this.sitekey, secret: this.secret, fields, ...(token ? { response: token } : {}) });
    if (!r || r.success !== true) return { verdict: this.failOpen ? 'allow' : 'review', risk: 0, reasons: ['service-unreachable'], unreachable: true, raw: r ?? {} };
    return { verdict: r.verdict ?? 'allow', risk: r.risk ?? 0, reasons: r.reasons ?? [], unreachable: false, raw: r };
  }

  /** Rückmeldung 'spam' | 'ham' → das System lernt E-Mail und IP als eigene Regel. */
  async report(kind, fields) {
    const r = await this._post('/captcha/v1/report', { sitekey: this.sitekey, secret: this.secret, kind, fields });
    return r?.success === true;
  }

  /**
   * Token selbst beschaffen (Server-zu-Server, Skripte, mobile Backends) – ohne Browser. Die Aufgabe wird gerechnet (je nach Schwierigkeit Sekundenbruchteile
   * bis wenige Sekunden); `origin` muss zu den Hosts der Domain passen (z. B. 'https://shop.example.com'). Gedacht, um offene Endpunkte teuer zu machen,
   * nicht um Menschen zu prüfen. → Token (String) oder null.
   */
  async getToken(action, { origin, signals } = {}) {
    const hdr = { 'Content-Type': 'text/plain', ...(origin ? { Origin: origin } : {}) };
    const post = async (p, body) => { try { const r = await this._fetch(this.base + p, { method: 'POST', headers: hdr, body: JSON.stringify(body), signal: AbortSignal.timeout(this.timeoutMs * 6) }); return await r.json(); } catch { return null; } };
    const ch = await post('/captcha/v1/challenge', { sitekey: this.sitekey, action });
    if (!ch?.challenge) return null;
    const nonce = solvePow(ch.challenge.id, ch.challenge.bits);
    const r = await post('/captcha/v1/solve', { challenge: ch.challenge, nonce: String(nonce), signals: { hp: '', t: 2500, wd: false, hl: false, ia: 0, ...(signals ?? {}) } });
    return r?.token ?? null;
  }

  /** Express-/Connect-Middleware: prüft `empedia-captcha-token` (Body oder Header X-Captcha-Token), antwortet bei Fehler mit 400. */
  middleware({ action, onFail } = {}) {
    return async (req, res, next) => {
      const token = req.body?.[TOKEN_FIELD] ?? req.get?.('x-captcha-token') ?? req.headers?.['x-captcha-token'];
      const r = await this.verify(token, action);
      if (r.success) return next();
      if (onFail) return onFail(req, res, r);
      res.status(400).json({ success: false, error: 'captcha_failed', codes: r.errorCodes });
    };
  }

  scriptTag() { return `<script src="${esc(this.base)}/captcha/v1/widget.js" async defer></script>`; }
  widgetTag(action = 'form', { mode, badge } = {}) {
    return `<div class="empedia-captcha" data-sitekey="${esc(this.sitekey)}" data-action="${esc(action)}"${mode ? ` data-mode="${esc(mode)}"` : ''}${badge === false ? ' data-badge="false"' : ''}></div>`;
  }
}
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
export default EmpediaCaptcha;
