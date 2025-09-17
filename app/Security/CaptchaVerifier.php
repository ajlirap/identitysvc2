<?php

namespace App\Security;

use Illuminate\Support\Facades\Http;

class CaptchaVerifier
{
    public function enabled(): bool
    {
        $v = config('identity.captcha.enabled');
        return filter_var($v, FILTER_VALIDATE_BOOLEAN);
    }

    public function verify(?string $token, ?string $ip = null): bool
    {
        if (!$this->enabled()) {
            return true;
        }
        $token = trim((string) $token);
        if ($token === '') {
            return false;
        }

        $provider = (string) config('identity.captcha.provider', 'recaptcha');
        $secret = (string) config('identity.captcha.secret');
        $verifyUrl = (string) data_get(config('identity.captcha.verify_url'), $provider, '');

        if ($secret === '' || $verifyUrl === '') {
            // Hard fail if misconfigured while enabled
            return false;
        }

        $payload = [
            'secret' => $secret,
            'response' => $token,
        ];
        if ($ip) {
            $payload['remoteip'] = $ip;
        }

        $resp = Http::asForm()->timeout(5)->post($verifyUrl, $payload);
        if (!$resp->ok()) {
            return false;
        }
        $data = $resp->json();
        $success = (bool) ($data['success'] ?? false);

        if ($provider === 'recaptcha') {
            $score = (float) ($data['score'] ?? 0.0);
            $min = (float) (config('identity.captcha.min_score', 0.5));
            return $success && $score >= $min;
        }

        // Turnstile only has success boolean
        return $success;
    }
}
