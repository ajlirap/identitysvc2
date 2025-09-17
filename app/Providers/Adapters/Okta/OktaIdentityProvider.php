<?php

namespace App\Providers\Adapters\Okta;

use App\Contracts\IdentityProvider;
use App\DTO\Tokens;
use App\DTO\UserProfile;

class OktaIdentityProvider implements IdentityProvider
{
    public function authorizeUrl(array $extra = []): string
    {
        $issuer = rtrim((string) config('identity.okta.issuer'), '/');
        $authorize = $issuer.'/v1/authorize';
        $q = http_build_query(array_filter([
            'client_id' => (string) config('identity.okta.client_id'),
            'response_type' => 'code',
            'redirect_uri' => (string) config('identity.okta.redirect_uri'),
            'scope' => 'openid profile email offline_access',
            'code_challenge' => $extra['code_challenge'] ?? null,
            'code_challenge_method' => isset($extra['code_challenge']) ? 'S256' : null,
            'state' => $extra['state'] ?? null,
            'nonce' => $extra['nonce'] ?? null,
        ]));
        return $authorize."?{$q}";
    }

    public function exchangeCode(string $code, string $codeVerifier): Tokens
    {
        $issuer = rtrim((string) config('identity.okta.issuer'), '/');
        $resp = \Illuminate\Support\Facades\Http::asForm()
            ->post($issuer.'/v1/token', [
                'grant_type' => 'authorization_code',
                'client_id' => (string) config('identity.okta.client_id'),
                'client_secret' => (string) config('identity.okta.client_secret'),
                'redirect_uri' => (string) config('identity.okta.redirect_uri'),
                'code' => $code,
                'code_verifier' => $codeVerifier,
            ])->throw()->json();

        return new Tokens(
            accessToken: $resp['access_token'],
            refreshToken: $resp['refresh_token'] ?? null,
            expiresIn: (int) ($resp['expires_in'] ?? 3600),
            idToken: $resp['id_token'] ?? null,
            tokenType: $resp['token_type'] ?? 'Bearer',
        );
    }

    public function refresh(string $refreshToken): Tokens
    {
        $issuer = rtrim((string) config('identity.okta.issuer'), '/');
        $resp = \Illuminate\Support\Facades\Http::asForm()
            ->post($issuer.'/v1/token', [
                'grant_type' => 'refresh_token',
                'client_id' => (string) config('identity.okta.client_id'),
                'client_secret' => (string) config('identity.okta.client_secret'),
                'refresh_token' => $refreshToken,
            ])->throw()->json();

        return new Tokens(
            accessToken: $resp['access_token'],
            refreshToken: $resp['refresh_token'] ?? null,
            expiresIn: (int) ($resp['expires_in'] ?? 3600),
            idToken: $resp['id_token'] ?? null,
            tokenType: $resp['token_type'] ?? 'Bearer',
        );
    }

    public function userInfo(string $accessToken): UserProfile
    {
        $issuer = rtrim((string) config('identity.okta.issuer'), '/');
        $res = \Illuminate\Support\Facades\Http::withToken($accessToken)
            ->get($issuer.'/v1/userinfo')
            ->throw()->json();

        return new UserProfile(
            id: (string) ($res['sub'] ?? ''),
            email: (string) ($res['email'] ?? ''),
            givenName: $res['given_name'] ?? null,
            familyName: $res['family_name'] ?? null,
            displayName: $res['name'] ?? null,
            roles: (array) ($res['roles'] ?? []),
            attributes: $res,
        );
    }

    public function issuer(): string { return (string) config('identity.okta.issuer'); }
    public function jwksUri(): string { return (string) config('identity.okta.jwks_uri'); }
    public function audience(): string { return (string) config('identity.common.audience'); }
}
