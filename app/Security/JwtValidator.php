<?php

namespace App\Security;

use Firebase\JWT\JWT;
use Firebase\JWT\JWK as FirebaseJWK;
use Illuminate\Support\Arr;
use UnexpectedValueException;

class JwtValidator
{
    public function __construct(private JwksCache $cache) {}

    public function validate(string $jwt, string $issuer, string $audience, string $jwksUri, int $leeway = 60): array
    {
        [$headerB64] = explode('.', $jwt);
        $header = json_decode(base64_decode($headerB64), true);
        $kid = $header['kid'] ?? null;
        $alg = $header['alg'] ?? null;
        if (!$kid || !$alg) {
            throw new UnexpectedValueException('Invalid JWT header');
        }

        $keys = $this->cache->get($jwksUri, (int) config('identity.common.cache_ttl'));
        $jwk = collect($keys)->firstWhere('kid', $kid);
        if (!$jwk) {
            // Force refresh once, then fail
            $this->cache->get($jwksUri, 1);
            $keys = $this->cache->get($jwksUri, (int) config('identity.common.cache_ttl'));
            $jwk = collect($keys)->firstWhere('kid', $kid);
            if (!$jwk) {
                throw new UnexpectedValueException('Unknown signing key');
            }
        }

        JWT::$leeway = $leeway;
        $key = FirebaseJWK::parseKey($jwk, $alg);
        $decoded = (array) JWT::decode($jwt, $key);

        if (($decoded['iss'] ?? null) !== $issuer) {
            throw new UnexpectedValueException('Bad issuer');
        }
        $aud = Arr::wrap($decoded['aud'] ?? []);
        if (!in_array($audience, $aud, true)) {
            throw new UnexpectedValueException('Bad audience');
        }
        return $decoded;
    }
}

