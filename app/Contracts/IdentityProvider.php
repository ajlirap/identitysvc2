<?php

namespace App\Contracts;

use App\DTO\Tokens;
use App\DTO\UserProfile;

interface IdentityProvider
{
    public function authorizeUrl(array $extra = []): string; // builds OIDC/PKCE URL
    public function exchangeCode(string $code, string $codeVerifier): Tokens; // auth code -> tokens
    public function refresh(string $refreshToken): Tokens; // rotate refresh
    public function userInfo(string $accessToken): UserProfile; // normalized claims

    public function issuer(): string;
    public function jwksUri(): string;
    public function audience(): string; // expected audience for APIs
}

