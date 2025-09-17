<?php

namespace App\Providers\Adapters\B2C;

use App\Contracts\IdentityProvider;
use App\DTO\Tokens;
use App\DTO\UserProfile;
use Illuminate\Support\Facades\Http;
use RuntimeException;

class B2CIdentityProvider implements IdentityProvider
{
    private array $metadataCache = [];

    public function authorizeUrl(array $extra = []): string
    {
        $endpoint = $this->resolveAuthorizeEndpoint();
        $q = http_build_query(array_filter([
            'client_id' => config('identity.b2c.client_id'),
            'response_type' => 'code',
            'redirect_uri' => config('identity.b2c.redirect_uri'),
            'scope' => config('identity.b2c.scope'),
            'response_mode' => 'query',
            'code_challenge' => $extra['code_challenge'] ?? null,
            'code_challenge_method' => isset($extra['code_challenge']) ? 'S256' : null,
            'state' => $extra['state'] ?? null,
            'nonce' => $extra['nonce'] ?? null,
        ]));

        $endpoint = rtrim($endpoint, '?');
        $separator = str_contains($endpoint, '?') ? '&' : '?';

        return $endpoint . $separator . $q;
    }

    public function exchangeCode(string $code, string $codeVerifier): Tokens
    {
        $payload = [
            'grant_type' => 'authorization_code',
            'client_id' => (string) config('identity.b2c.client_id'),
            'client_secret' => (string) config('identity.b2c.client_secret'),
            'redirect_uri' => (string) config('identity.b2c.redirect_uri'),
            'scope' => (string) config('identity.b2c.scope'),
            'code' => $code,
        ];
        if ($codeVerifier !== '') {
            $payload['code_verifier'] = $codeVerifier;
        }

        $endpoint = $this->resolveTokenEndpoint();
        $resp = Http::asForm()->post($endpoint, $payload)->throw()->json();

        return new Tokens(
            accessToken: $resp['access_token'] ?? null,
            refreshToken: $resp['refresh_token'] ?? null,
            expiresIn: (int) ($resp['expires_in'] ?? 3600),
            idToken: $resp['id_token'] ?? null,
            tokenType: $resp['token_type'] ?? 'Bearer',
        );
    }

    public function refresh(string $refreshToken): Tokens
    {
        $endpoint = $this->resolveTokenEndpoint();
        $resp = Http::asForm()
            ->post($endpoint, [
                'grant_type' => 'refresh_token',
                'client_id' => (string) config('identity.b2c.client_id'),
                'client_secret' => (string) config('identity.b2c.client_secret'),
                'refresh_token' => $refreshToken,
                'scope' => (string) config('identity.b2c.scope'),
            ])->throw()->json();

        return new Tokens(
            accessToken: $resp['access_token'] ?? null,
            refreshToken: $resp['refresh_token'] ?? null,
            expiresIn: (int) ($resp['expires_in'] ?? 3600),
            idToken: $resp['id_token'] ?? null,
            tokenType: $resp['token_type'] ?? 'Bearer',
        );
    }

    public function userInfo(string $accessToken): UserProfile
    {
        $parts = explode('.', $accessToken);
        $claims = json_decode(base64_decode($parts[1] ?? ''), true) ?: [];

        return new UserProfile(
            id: (string) ($claims['sub'] ?? $claims['oid'] ?? ''),
            email: (string) ($claims['emails'][0] ?? $claims['preferred_username'] ?? ''),
            givenName: $claims['given_name'] ?? null,
            familyName: $claims['family_name'] ?? null,
            displayName: $claims['name'] ?? null,
            roles: (array) ($claims['roles'] ?? []),
            attributes: $claims,
        );
    }

    public function issuer(): string
    {
        $configured = (string) config('identity.b2c.issuer');
        if ($configured !== '') {
            return $configured;
        }
        return (string) ($this->metadataValue('issuer') ?? '');
    }

    public function jwksUri(): string
    {
        $configured = (string) config('identity.b2c.jwks_uri');
        if ($configured !== '') {
            return $configured;
        }
        return (string) ($this->metadataValue('jwks_uri') ?? '');
    }

    public function audience(): string
    {
        return (string) config('identity.common.audience');
    }

    private function resolveAuthorizeEndpoint(): string
    {
        $configured = (string) config('identity.b2c.authorize_endpoint');
        if ($configured !== '') {
            return $configured;
        }

        $endpoint = (string) ($this->metadataValue('authorization_endpoint') ?? '');
        if ($endpoint === '') {
            throw new RuntimeException('Azure B2C authorize endpoint is not configured.');
        }

        return $endpoint;
    }

    private function resolveTokenEndpoint(): string
    {
        $configured = (string) config('identity.b2c.token_endpoint');
        if ($configured !== '') {
            return $configured;
        }

        $endpoint = (string) ($this->metadataValue('token_endpoint') ?? '');
        if ($endpoint === '') {
            throw new RuntimeException('Azure B2C token endpoint is not configured.');
        }

        return $endpoint;
    }

    private function metadataValue(string $key): ?string
    {
        $policy = (string) config('identity.b2c.policy_signin');
        if ($policy === '') {
            return null;
        }

        $metadata = $this->policyMetadata($policy);
        $value = $metadata[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    private function policyMetadata(string $policy): array
    {
        if ($policy === '') {
            return [];
        }

        if (isset($this->metadataCache[$policy])) {
            return $this->metadataCache[$policy];
        }

        $url = $this->policyDiscoveryUrl($policy);
        if (!$url) {
            return $this->metadataCache[$policy] = [];
        }

        try {
            $data = Http::get($url)->throw()->json();
            if (!is_array($data)) {
                $data = [];
            }
        } catch (\Throwable $e) {
            $data = [];
        }

        return $this->metadataCache[$policy] = $data;
    }

    private function policyDiscoveryUrl(string $policy): ?string
    {
        $configured = (string) config('identity.b2c.discovery_endpoint');
        if ($configured !== '') {
            if (str_contains($configured, '{policy}')) {
                return str_replace('{policy}', $policy, $configured);
            }

            if (str_contains($configured, '.well-known/openid-configuration')) {
                return $configured;
            }

            return rtrim($configured, '/') . '/' . $policy . '/v2.0/.well-known/openid-configuration';
        }

        $host = $this->preferredHost();
        $tenantSegment = $this->tenantSegment();
        if ($host === null || $tenantSegment === null) {
            return null;
        }

        return "https://{$host}/{$tenantSegment}/{$policy}/v2.0/.well-known/openid-configuration";
    }

    private function preferredHost(): ?string
    {
        $domain = $this->normalizeHost((string) config('identity.b2c.domain'));
        if ($domain !== null) {
            return $domain;
        }

        $tenant = trim((string) config('identity.b2c.tenant'));
        if ($tenant === '') {
            return null;
        }

        $tenantName = $tenant;
        if (str_contains($tenant, '.')) {
            $tenantName = preg_replace('/\\.onmicrosoft\\.com$/i', '', $tenantName);
        }

        $tenantName = preg_replace('/\\.b2clogin\\.com$/i', '', $tenantName ?? '');
        if ($tenantName === '') {
            return null;
        }

        return strtolower($tenantName) . '.b2clogin.com';
    }

    private function tenantSegment(): ?string
    {
        $segment = trim((string) config('identity.b2c.tenant_id'));
        if ($segment === '') {
            $segment = trim((string) config('identity.b2c.tenant'));
        }

        if ($segment === '') {
            return null;
        }

        if (!str_contains($segment, '.') && !preg_match('/^[0-9a-fA-F-]{32,}$/', $segment)) {
            $segment .= '.onmicrosoft.com';
        }

        return trim($segment, '/');
    }

    private function normalizeHost(string $domain): ?string
    {
        $domain = trim($domain);
        if ($domain === '') {
            return null;
        }

        if (preg_match('#^https?://#i', $domain)) {
            $host = parse_url($domain, PHP_URL_HOST);
            $domain = $host ?: '';
        }

        $domain = trim($domain, '/');
        if ($domain === '') {
            return null;
        }

        if (str_contains($domain, '/')) {
            $parts = parse_url('https://' . $domain);
            $domain = $parts['host'] ?? '';
        }

        return $domain !== '' ? strtolower($domain) : null;
    }
}