<?php

namespace App\Security;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;

class JwksCache
{
    public function get(string $jwksUri, int $ttl): array
    {
        return Cache::remember("jwks:".$jwksUri, $ttl, function () use ($jwksUri) {
            $resp = Http::timeout(5)->get($jwksUri);
            $resp->throw();
            return $resp->json('keys', []);
        });
    }
}

