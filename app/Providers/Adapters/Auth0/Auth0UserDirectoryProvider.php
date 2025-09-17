<?php

namespace App\Providers\Adapters\Auth0;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;

class Auth0UserDirectoryProvider implements UserDirectoryProvider
{
    private function mgmtToken(): string
    {
        $domain = rtrim((string) config('identity.auth0.domain'), '/');
        $resp = \Illuminate\Support\Facades\Http::asForm()
            ->post("https://{$domain}/oauth/token", [
                'grant_type' => 'client_credentials',
                'client_id' => (string) config('identity.auth0.mgmt_client_id'),
                'client_secret' => (string) config('identity.auth0.mgmt_client_secret'),
                'audience' => (string) config('identity.auth0.mgmt_audience'),
            ])->throw()->json();
        return $resp['access_token'];
    }

    public function create(UserCreateRequest $req): UserProfile
    {
        $t = $this->mgmtToken();
        $body = [
            'email' => $req->email,
            'name' => trim(($req->givenName.' '.$req->familyName) ?: $req->email),
            'connection' => 'Username-Password-Authentication',
            'verify_email' => false,
        ];
        if (!$req->invite) {
            $body['password'] = bin2hex(random_bytes(8)).'!Aa1';
        }
        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->post("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/users", $body)
            ->throw()->json();

        return new UserProfile(
            id: (string) $res['user_id'],
            email: (string) $res['email'],
            displayName: (string) ($res['name'] ?? $res['email']),
            status: $req->invite ? 'invited' : 'active',
            attributes: ['raw' => $res],
        );
    }

    public function findById(string $id): ?UserProfile
    {
        $t = $this->mgmtToken();
        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->get("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/users/".rawurlencode($id))
            ->throw()->json();
        if (!$res || !isset($res['user_id'])) return null;
        return new UserProfile(
            id: (string) $res['user_id'],
            email: (string) ($res['email'] ?? ''),
            displayName: (string) ($res['name'] ?? ($res['email'] ?? '')),
            status: ($res['blocked'] ?? false) ? 'inactive' : 'active',
            attributes: ['raw' => $res],
        );
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $t = $this->mgmtToken();
        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->get("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/users-by-email?email=".rawurlencode($email))
            ->throw()->json();
        $u = $res[0] ?? null;
        if (!$u) return null;
        return new UserProfile(
            id: (string) $u['user_id'],
            email: (string) ($u['email'] ?? ''),
            displayName: (string) ($u['name'] ?? ($u['email'] ?? '')),
            status: ($u['blocked'] ?? false) ? 'inactive' : 'active',
            attributes: ['raw' => $u],
        );
    }

    public function deactivate(string $id): void
    {
        $t = $this->mgmtToken();
        \Illuminate\Support\Facades\Http::withToken($t)
            ->patch("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/users/".rawurlencode($id), [
                'blocked' => true,
            ])->throw();
    }

    public function activate(string $id): void
    {
        $t = $this->mgmtToken();
        \Illuminate\Support\Facades\Http::withToken($t)
            ->patch("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/users/".rawurlencode($id), [
                'blocked' => false,
            ])->throw();
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // Typically front-end redirects to /u/reset-password hosted page.
    }

    public function adminResetPassword(string $id): void
    {
        $t = $this->mgmtToken();
        \Illuminate\Support\Facades\Http::withToken($t)
            ->post("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/tickets/password-change", [
                'user_id' => $id,
            ])->throw();
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $t = $this->mgmtToken();
        $page = is_numeric($cursor ?? '') ? (int) $cursor : 0;
        $params = [
            'per_page' => max(1, min(100, $limit)),
            'page' => max(0, $page),
        ];
        if ($query !== null && $query !== '') {
            $params['q'] = $query;
            $params['search_engine'] = 'v3';
        }

        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->get("https://".rtrim((string) config('identity.auth0.domain'), '/')."/api/v2/users", $params)
            ->throw()->json();

        $items = [];
        foreach (($res ?? []) as $u) {
            if (!is_array($u)) continue;
            $items[] = new UserProfile(
                id: (string) ($u['user_id'] ?? ''),
                email: (string) ($u['email'] ?? ''),
                displayName: (string) ($u['name'] ?? ($u['email'] ?? '')),
                status: ($u['blocked'] ?? false) ? 'inactive' : 'active',
                attributes: ['raw' => $u],
            );
        }

        $nextCursor = (count($items) >= ($params['per_page'] ?? 50)) ? (string)($page + 1) : null;
        return [ 'items' => $items, 'nextCursor' => $nextCursor ];
    }
}
