<?php

namespace App\Providers\Adapters\B2C;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;
use App\Support\B2C\GraphClient;

class B2CUserDirectoryProvider implements UserDirectoryProvider
{
    public function __construct(private readonly GraphClient $graph)
    {
    }
    private function discoverTokenEndpoint(): string
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        if ($tenant === '') {
            return '';
        }
        $discoveryUrl = "https://login.microsoftonline.com/{$tenant}/.well-known/openid-configuration";
        try {
            $conf = Http::get($discoveryUrl)->throw()->json();
            return (string) ($conf['token_endpoint'] ?? '');
        } catch (\Throwable $e) {
            return '';
        }
    }

    private function graphAccessToken(): string
    {
        $tenant = (string) config('identity.b2c.graph_tenant');
        $endpoint = (string) (config('identity.b2c.graph_token_endpoint') ?: $this->discoverTokenEndpoint() ?: ("https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token"));

        $clientId = (string) config('identity.b2c.graph_client_id');
        $clientSecret = (string) config('identity.b2c.graph_client_secret');
        $configuredScope = (string) config('identity.b2c.graph_scope');

        $isV1 = str_contains($endpoint, '/oauth2/token') && !str_contains($endpoint, '/oauth2/v2.0/');
        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];
        if ($isV1) {
            // AAD v1 endpoint expects 'resource' instead of 'scope'
            $resource = $configuredScope;
            if ($resource === '' || str_ends_with($resource, '/.default')) {
                $resource = 'https://graph.microsoft.com';
            } else {
                // If scope was provided like 'https://graph.microsoft.com/.default', strip suffix
                $resource = rtrim(preg_replace('#/\.default$#', '', $resource) ?: $resource, '/');
            }
            $form['resource'] = $resource;
        } else {
            // v2 endpoint expects 'scope' (usually '.../.default')
            $scope = $configuredScope !== '' ? $configuredScope : 'https://graph.microsoft.com/.default';
            $form['scope'] = $scope;
        }

        $resp = Http::asForm()->post($endpoint, $form)->throw()->json();
        return $resp['access_token'];
    }

    public function create(UserCreateRequest $req): UserProfile
    {
        $email = mb_strtolower($req->email);
        $body = [
            'accountEnabled' => true,
            'displayName' => trim(($req->givenName . ' ' . $req->familyName) ?: $email),
            'identities' => [[
                'signInType' => 'emailAddress',
                'issuer' => (string) config('identity.b2c.tenant'),
                'issuerAssignedId' => $email,
            ]],
        ];
        if (!$req->invite) {
            $body['passwordProfile'] = [
                'password' => bin2hex(random_bytes(8)) . '!Aa1',
                'forceChangePasswordNextSignIn' => true,
            ];
        }

        $res = $this->graph->post('https://graph.microsoft.com/v1.0/users', $body)->json();

        return new UserProfile(
            id: $res['id'],
            email: $email,
            displayName: $res['displayName'] ?? $email,
            status: $req->invite ? 'invited' : 'active',
            attributes: ['raw' => $res],
        );
    }

    public function findById(string $id): ?UserProfile
    {
        $res = $this->graph->get("https://graph.microsoft.com/v1.0/users/{$id}")->json();

        if (!$res || !isset($res['id'])) return null;

        $email = $res['identities'][0]['issuerAssignedId'] ?? '';
        return new UserProfile(
            id: $res['id'],
            email: $email,
            displayName: $res['displayName'] ?? $email,
            status: ($res['accountEnabled'] ?? true) ? 'active' : 'inactive',
            attributes: ['raw' => $res],
        );
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $email = mb_strtolower($email);
        $filter = rawurlencode(
            "identities/any(c:c/issuerAssignedId eq '{$email}' and c/issuer eq '" . config('identity.b2c.tenant') . "')"
        );
        $res = $this->graph->get("https://graph.microsoft.com/v1.0/users?\$filter={$filter}&\$select=id,displayName,identities,accountEnabled")->json();

        $u = $res['value'][0] ?? null;
        if (!$u) return null;

        return new UserProfile(
            id: $u['id'],
            email: $email,
            displayName: $u['displayName'] ?? $email,
            status: ($u['accountEnabled'] ?? true) ? 'active' : 'inactive',
            attributes: ['raw' => $u],
        );
    }

    public function deactivate(string $id): void
    {
        $this->graph->patch("https://graph.microsoft.com/v1.0/users/{$id}", ['accountEnabled' => false]);
    }

    public function activate(string $id): void
    {
        $this->graph->patch("https://graph.microsoft.com/v1.0/users/{$id}", ['accountEnabled' => true]);
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // No server action: front-end should redirect to B2C password-reset policy authorize URL.
    }

    public function adminResetPassword(string $id): void
    {
        $temp = bin2hex(random_bytes(8)) . '!Aa1';
        $this->graph->patch("https://graph.microsoft.com/v1.0/users/{$id}", [
            'passwordProfile' => [
                'password' => $temp,
                'forceChangePasswordNextSignIn' => true,
            ],
        ]);
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $params = ['$top' => max(1, min(100, $limit))];
        if ($cursor) {
            // Graph uses $skiptoken; pass-through as provided
            $params['$skiptoken'] = $cursor;
        }
        if ($query !== null && $query !== '') {
            // Best-effort: filter by displayName prefix
            $escaped = str_replace("'", "''", $query);
            $filterParam = '$filter=' . rawurlencode("startswith(displayName,'{$escaped}')");
            // We'll append as raw string to avoid double-encoding by client params
            $queryString = http_build_query($params);
            $url = 'https://graph.microsoft.com/v1.0/users?' . $queryString . '&' . $filterParam;
            $resp = $this->graph->get($url);
        } else {
            // List all users using Graph-compatible filter hint
            $queryString = http_build_query($params);
            $url = 'https://graph.microsoft.com/v1.0/users?%24filter%20all=null' . ($queryString ? ('&' . $queryString) : '');
            $resp = $this->graph->get($url);
        }

        $data = $resp->json();
        $itemsRaw = $data['value'] ?? [];
        $items = [];
        foreach (($itemsRaw ?? []) as $u) {
            if (!is_array($u)) continue;
            $email = $u['identities'][0]['issuerAssignedId'] ?? ($u['mail'] ?? '');
            $items[] = new UserProfile(
                id: (string) ($u['id'] ?? ''),
                email: (string) $email,
                displayName: (string) ($u['displayName'] ?? $email),
                status: ($u['accountEnabled'] ?? true) ? 'active' : 'inactive',
                attributes: ['raw' => $u],
            );
        }

        $nextLink = (string) ($data['@odata.nextLink'] ?? '');
        $nextCursor = null;
        if ($nextLink) {
            // Parse $skiptoken from nextLink
            $parts = parse_url($nextLink);
            if (!empty($parts['query'])) {
                parse_str($parts['query'], $q);
                if (!empty($q['$skiptoken'])) {
                    $nextCursor = (string) $q['$skiptoken'];
                }
            }
        }

        return ['items' => $items, 'nextCursor' => $nextCursor];
    }
}
