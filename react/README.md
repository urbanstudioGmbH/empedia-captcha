# @urbanstudio/empedia-captcha-react

Bot-Schutz ohne Cookies für React und Next.js.

```jsx
'use client';
import { useState } from 'react';
import { EmpediaCaptcha } from '@urbanstudio/empedia-captcha-react';

export function ContactForm({ action }) {
  const [token, setToken] = useState('');
  return (
    <form action={action}>
      <input name="email" type="email" required />
      <EmpediaCaptcha sitekey="ek_site_…" base="https://captcha.example.com" action="contact" onToken={setToken} />
      <input type="hidden" name="empedia-captcha-token" value={token} />
      <button>Senden</button>
    </form>
  );
}
```

Serverseitig (Next.js Route Handler / Server Action) prüfen Sie das Token mit `@urbanstudio/empedia-captcha`:

```js
import { EmpediaCaptcha as Captcha } from '@urbanstudio/empedia-captcha';
const captcha = Captcha.fromEnv(); // EMPEDIA_CAPTCHA_SITEKEY / _SECRET / _BASE
const r = await captcha.verify(formData.get('empedia-captcha-token'), 'contact');
if (!r.success) return new Response('Bitte erneut versuchen', { status: 400 });
```

Das Secret gehört nur in eine Server-Umgebungsvariable, nie in den Browser.
