<?php
declare(strict_types=1);

namespace Empedia\Captcha;

/**
 * Standard-Transport des Clients: cURL, sonst PHP-Streams. Liefert den Antworttext (unabhängig vom Statuscode) oder null bei Verbindungsfehler.
 * Wird vom Client erst bei Bedarf geladen; wer einen eigenen `transport` übergibt, braucht diese Datei nicht.
 */
final class HttpTransport
{
    /** @param string[] $headers vollständige Zeilen, z. B. 'Content-Type: application/json' */
    public static function send(string $method, string $url, ?string $body, array $headers, float $timeout): ?string
    {
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            $o = [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => (int) ceil($timeout), CURLOPT_CONNECTTIMEOUT => 3];
            if ($method === 'POST') { $o[CURLOPT_POST] = true; $o[CURLOPT_POSTFIELDS] = (string) $body; }
            if ($headers) { $o[CURLOPT_HTTPHEADER] = $headers; }
            curl_setopt_array($ch, $o);
            $res = curl_exec($ch);
            curl_close($ch);
            return $res === false ? null : (string) $res;
        }
        $http = ['method' => $method, 'timeout' => $timeout, 'ignore_errors' => true];
        if ($headers) { $http['header'] = implode("\r\n", $headers) . "\r\n"; }
        if ($body !== null) { $http['content'] = $body; }
        $res = @file_get_contents($url, false, stream_context_create(['http' => $http]));
        return $res === false ? null : (string) $res;
    }
}
