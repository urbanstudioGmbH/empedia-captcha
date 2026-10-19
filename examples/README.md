# Beispiele für Frameworks

Die Prüfung läuft immer **serverseitig** mit dem Secret (Umgebungsvariable `EMPEDIA_CAPTCHA_SECRET`); im Browser wird nur das Widget mit dem Website-Schlüssel geladen. Das Token steht im Formularfeld `empedia-captcha-token`.

## Laravel (PHP-SDK)

```bash
composer require urbanstudio/empedia-captcha
```

`.env`: `EMPEDIA_CAPTCHA_SITEKEY=…`, `EMPEDIA_CAPTCHA_SECRET=…`, `EMPEDIA_CAPTCHA_BASE=https://captcha.example.com`

```php
// app/Rules/Captcha.php
use Closure; use Empedia\Captcha\Client; use Illuminate\Contracts\Validation\ValidationRule;

class Captcha implements ValidationRule {
    public function __construct(private string $action = 'form') {}
    public function validate(string $attribute, mixed $value, Closure $fail): void {
        if (!Client::fromEnv(['failOpen' => true])->verify($value, $this->action)->success) { $fail('Die Sicherheitsprüfung ist fehlgeschlagen. Bitte versuchen Sie es erneut.'); }
    }
}
// Controller
$request->validate(['email' => 'required|email', 'empedia-captcha-token' => ['required', new Captcha('contact')]]);
```

Blade: `{!! Empedia\Captcha\Widget::script(env('EMPEDIA_CAPTCHA_BASE')) !!}` einmal je Seite und `{!! Empedia\Captcha\Widget::element(env('EMPEDIA_CAPTCHA_SITEKEY'), 'contact') !!}` im Formular.

## Symfony (PHP-SDK)

```php
// src/Validator/CaptchaValidator.php (vereinfacht)
use Empedia\Captcha\Client;
final class CaptchaService { public function __construct(private Client $client) {}
    public function ok(Request $r, string $action): bool { return $this->client->verify($r->request->get('empedia-captcha-token'), $action)->success; } }
// config/services.yaml
services:
    Empedia\Captcha\Client:
        factory: ['Empedia\Captcha\Client', 'fromEnv']
        arguments: [{ failOpen: true }]
```

Im Controller: `if (!$captcha->ok($request, 'contact')) { /* Formular erneut anzeigen */ }`.

## Vue 3

```vue
<script setup>
import { onMounted, ref } from 'vue';
const token = ref(''); const el = ref(null);
onMounted(() => {
  const s = document.createElement('script'); s.src = 'https://captcha.example.com/captcha/v1/widget.js'; s.async = true;
  s.onload = () => window.EmpediaCaptcha.render(el.value);
  document.head.appendChild(s);
  el.value.addEventListener('empedia-captcha-ready', (e) => (token.value = e.detail.token));
});
</script>
<template>
  <form @submit.prevent="send">
    <input v-model="email" type="email" required>
    <div ref="el" class="empedia-captcha" data-sitekey="ek_site_…" data-action="contact"></div>
    <button>Senden</button>
  </form>
</template>
```

Beim Senden das Token mitschicken (`{ email, 'empedia-captcha-token': token }`) und auf dem Server mit einem SDK prüfen. Nach einer abgelehnten Anfrage das Widget zurücksetzen: `window.EmpediaCaptcha.reset(el.value)`.

## Svelte

```svelte
<script>
  import { onMount } from 'svelte';
  let el, token = '';
  onMount(() => {
    const s = document.createElement('script'); s.src = 'https://captcha.example.com/captcha/v1/widget.js'; s.async = true;
    s.onload = () => window.EmpediaCaptcha.render(el);
    document.head.appendChild(s);
    el.addEventListener('empedia-captcha-ready', (e) => (token = e.detail.token));
  });
</script>
<form method="post">
  <div bind:this={el} class="empedia-captcha" data-sitekey="ek_site_…" data-action="contact"></div>
  <input type="hidden" name="empedia-captcha-token" value={token}>
  <button>Senden</button>
</form>
```

## Ohne Browser (Server-zu-Server, Skripte, mobile Backends)

Die SDKs rechnen die Aufgabe selbst: Node `await captcha.getToken('api', { origin: 'https://shop.example.com' })`, PHP `$c->getToken('api', 'https://shop.example.com')`, Python `captcha.get_token('api', 'https://shop.example.com')`, Go `c.GetToken("api", "https://shop.example.com")`. Das macht offene Endpunkte für Massenabfragen teuer; es prüft keine Menschen.
