/**
 * EMPEDIAcaptcha – Seitenschutz (Vorschaltprüfung) für Node.js (Express/Connect, Node ≥ 18).
 *
 *   import { empediaGate } from './empedia-gate.mjs';
 *   app.use(empediaGate({ base: 'https://captcha.example.com', sitekey: 'ek_site_…', secret: process.env.EMPEDIA_CAPTCHA_SECRET }));
 *
 * Besucher ohne gültigen Durchlass werden kurz auf die Prüfseite des Dienstes geleitet; nach der Rückkehr prüft die Middleware das Token
 * (siteverify) und setzt einen eigenen, signierten Cookie („empedia_pass“, technisch notwendig). Ein-/Ausschalten, Gültigkeit und Ausnahmen
 * stellen Sie in der Oberfläche unter „Seitenschutz“ ein (Abruf alle 60 s). Ist der Dienst nicht erreichbar, werden alle Besucher durchgelassen.
 * Hinter einem Reverse-Proxy `app.set('trust proxy', 1)` setzen (für Protokoll und Adresse des Besuchers).
 */
import { createHmac, timingSafeEqual } from 'node:crypto';
import dns from 'node:dns/promises';

const b64 = (buf) => Buffer.from(buf).toString('base64url');
const sig = (exp, ua, secret) => b64(createHmac('sha256', secret).update(`${exp}|${ua}`).digest());
const parseCookies = (h) => Object.fromEntries(String(h || '').split(';').map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(p => p[0]));

export function empediaGate({ base, sitekey, secret, cookie = 'empedia_pass' } = {}) {
  if (!base || !sitekey || !secret) throw new Error('empediaGate: base, sitekey und secret sind erforderlich');
  base = String(base).replace(/\/$/, '');
  let cfg = null, cfgAt = 0;
  const bots = new Map(); // IP → { ok, at }

  async function config() {
    if (cfg && Date.now() - cfgAt < 60_000) return cfg;
    try {
      const r = await fetch(`${base}/captcha/v1/gate-config?sitekey=${encodeURIComponent(sitekey)}`, { signal: AbortSignal.timeout(4000) });
      if (r.ok) { const j = await r.json(); if (j && 'enabled' in j) { cfg = j; cfgAt = Date.now(); } }
    } catch { /* letzte bekannte Einstellung bleibt */ }
    if (!cfg) cfgAt = Date.now() - 50_000; // nach einem Fehlversuch in 10 s erneut versuchen
    return cfg;
  }

  async function isCrawler(ip) {
    if (!ip) return false;
    const c = bots.get(ip);
    if (c && Date.now() - c.at < 86_400_000) return c.ok;
    let ok = false;
    try {
      for (const host of await dns.reverse(ip)) {
        const h = host.toLowerCase();
        if (!(cfg.crawler_suffixes || []).some(s => h.endsWith(s))) continue;
        const fwd = [...(await dns.resolve4(h).catch(() => [])), ...(await dns.resolve6(h).catch(() => []))];
        if (fwd.includes(ip)) { ok = true; break; }
      }
    } catch { /* kein Eintrag: kein Robot */ }
    bots.set(ip, { ok, at: Date.now() });
    if (bots.size > 5000) bots.clear();
    return ok;
  }

  return async function gate(req, res, next) {
    try {
      const c = await config();
      if (!c || !c.enabled) return next();
      const path = (req.originalUrl || req.url || '/').split('?')[0];
      if ((c.skip || []).some(p => p && path.startsWith(p))) return next();
      const secure = req.secure || req.protocol === 'https';
      const host = req.headers.host || '';
      const current = (clean = false) => {
        const u = new URL(req.originalUrl || req.url, `${secure ? 'https' : 'http'}://${host}`);
        if (clean) u.searchParams.delete('empedia_gate');
        return u.toString();
      };
      const ua = String(req.headers['user-agent'] || '').slice(0, 200);

      const t = new URL(req.originalUrl || req.url, 'http://x').searchParams.get('empedia_gate');
      if (t) {
        let r = null;
        try { r = await (await fetch(`${base}/captcha/v1/siteverify`, { method: 'POST', body: new URLSearchParams({ secret, response: t, action: 'gate' }), signal: AbortSignal.timeout(4000) })).json(); } catch { /* ungültig */ }
        if (r && r.success === true && String(r.hostname || '').toLowerCase() === host.replace(/:\d+$/, '').toLowerCase()) {
          const exp = Math.floor(Date.now() / 1000) + Math.max(5, Number(c.ttl_min) || 60) * 60;
          res.cookie(cookie, `${exp}.${sig(exp, ua, secret)}`, { maxAge: (exp * 1000 - Date.now()), httpOnly: true, secure, sameSite: 'lax', path: '/' });
          res.set('Cache-Control', 'no-store');
          return res.redirect(302, current(true));
        }
        return res.status(403).type('text/plain').send('Verification failed.'); // keine erneute Weiterleitung: verhindert Schleifen
      }

      const m = /^(\d{9,11})\.([A-Za-z0-9_-]{43})$/.exec(parseCookies(req.headers.cookie)[cookie] || '');
      if (m && Number(m[1]) > Date.now() / 1000) {
        const a = Buffer.from(sig(m[1], ua, secret)), b = Buffer.from(m[2]);
        if (a.length === b.length && timingSafeEqual(a, b)) return next();
      }
      if (c.crawlers && await isCrawler(req.ip)) return next();

      const wantsHtml = (req.method === 'GET' || req.method === 'HEAD') && String(req.headers.accept || '').includes('text/html');
      if (wantsHtml) {
        res.set('Cache-Control', 'no-store');
        return res.redirect(302, `${base}/captcha/v1/gate?sitekey=${encodeURIComponent(sitekey)}&return=${encodeURIComponent(current())}`);
      }
      return res.status(403).type('text/plain').send('Forbidden.');
    } catch (e) { return next(); } // im Zweifel die Website nicht aussperren
  };
}
