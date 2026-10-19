// EMPEDIAcaptcha für React/Next.js (ohne Build-Schritt, keine Abhängigkeiten außer React).
// Browser: <EmpediaCaptcha sitekey base action="contact" onToken={setToken} />  oder  useEmpediaCaptcha(...).
// Server (Next.js Route/Server Action): das Token mit @urbanstudio/empedia-captcha prüfen (verify) – das Secret bleibt auf dem Server.
import { createElement, useCallback, useEffect, useRef, useState } from 'react';

const loading = new Map();

/** Lädt widget.js einmal je Dienst-Adresse. */
export function loadWidget(base) {
  const root = String(base || '').replace(/\/$/, '');
  if (typeof document === 'undefined' || !root) return Promise.reject(new Error('no-browser-or-base'));
  if (typeof window !== 'undefined' && window.EmpediaCaptcha && window.EmpediaCaptcha.execute) return Promise.resolve(window.EmpediaCaptcha);
  if (!loading.has(root)) {
    loading.set(root, new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = `${root}/captcha/v1/widget.js`; s.async = true;
      s.onload = () => (window.EmpediaCaptcha ? resolve(window.EmpediaCaptcha) : reject(new Error('widget-missing')));
      s.onerror = () => { loading.delete(root); reject(new Error('widget-load-failed')); };
      document.head.appendChild(s);
    }));
  }
  return loading.get(root);
}

/** Komponente: rendert das Widget in ein <div>; onToken(token) bei Erfolg, onError(code) bei Fehler. mode: focus | load | submit. */
export function EmpediaCaptcha({ sitekey, base, action = 'form', mode = 'focus', badge = true, onToken, onError, className }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current; if (!el) return undefined;
    const ok = (e) => onToken && onToken(e.detail.token);
    const bad = (e) => onError && onError(e.detail && e.detail.error);
    el.addEventListener('empedia-captcha-ready', ok); el.addEventListener('empedia-captcha-error', bad);
    let live = true;
    loadWidget(base).then((w) => { if (live) w.render(el); }).catch((err) => onError && onError(err.message));
    return () => { live = false; el.removeEventListener('empedia-captcha-ready', ok); el.removeEventListener('empedia-captcha-error', bad); };
  }, [base, sitekey, action, mode]); // eslint-disable-line react-hooks/exhaustive-deps
  return createElement('div', { ref, className: ['empedia-captcha', className].filter(Boolean).join(' '), 'data-sitekey': sitekey, 'data-action': action, 'data-mode': mode, ...(badge ? {} : { 'data-badge': 'false' }) });
}

/** Hook für „Token erst beim Absenden holen“: const { execute, busy } = useEmpediaCaptcha({ sitekey, base, action }); const token = await execute(); */
export function useEmpediaCaptcha({ sitekey, base, action = 'submit' }) {
  const [busy, setBusy] = useState(false);
  const execute = useCallback(async () => {
    setBusy(true);
    try { const w = await loadWidget(base); return await w.execute({ sitekey, action }); } finally { setBusy(false); }
  }, [base, sitekey, action]);
  return { execute, busy };
}

export default EmpediaCaptcha;
