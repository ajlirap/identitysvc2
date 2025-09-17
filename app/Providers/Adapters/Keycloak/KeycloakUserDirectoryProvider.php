<?php

namespace App\Providers\Adapters\Keycloak;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;

class KeycloakUserDirectoryProvider implements UserDirectoryProvider
{
    private function adminBase(): string
    {
        $base = rtrim((string) config('identity.keycloak.base_url'), '/');
        $realm = rawurlencode((string) config('identity.keycloak.realm'));
        return $base.'/admin/realms/'.$realm;
    }

    private function adminToken(): string
    {
        $base = rtrim((string) config('identity.keycloak.base_url'), '/');
        $realm = rawurlencode((string) config('identity.keycloak.realm'));
        $resp = \Illuminate\Support\Facades\Http::asForm()
            ->post($base.'/realms/'.$realm.'/protocol/openid-connect/token', [
                'grant_type' => 'client_credentials',
                'client_id' => (string) config('identity.keycloak.client_id'),
                'client_secret' => (string) config('identity.keycloak.client_secret'),
            ])->throw()->json();
        return $resp['access_token'];
    }

    public function create(UserCreateRequest $req): UserProfile
    {
        $t = $this->adminToken();
        $body = [
            'enabled' => !$req->invite,
            'username' => $req->email,
            'email' => $req->email,
            'firstName' => $req->givenName,
            'lastName' => $req->familyName,
            'emailVerified' => false,
        ];
        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->post($this->adminBase().'/users', $body)
            ->throw();

        $loc = $res->header('Location');
        $id = $loc ? basename($loc) : '';

        return new UserProfile(
            id: $id,
            email: $req->email,
            displayName: trim(($req->givenName.' '.$req->familyName) ?: $req->email),
            status: $req->invite ? 'invited' : 'active',
            attributes: ['location' => $loc],
        );
    }

    public function findById(string $id): ?UserProfile
    {
        $t = $this->adminToken();
        $u = \Illuminate\Support\Facades\Http::withToken($t)
            ->get($this->adminBase().'/users/'.rawurlencode($id))
            ->throw()->json();
        if (!$u || !isset($u['id'])) return null;
        return new UserProfile(
            id: (string) $u['id'],
            email: (string) ($u['email'] ?? ''),
            displayName: (string) (($u['firstName'] ?? '').' '.($u['lastName'] ?? '')),
            status: ($u['enabled'] ?? true) ? 'active' : 'inactive',
            attributes: ['raw' => $u],
        );
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $t = $this->adminToken();
        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->get($this->adminBase().'/users?email='.rawurlencode($email))
            ->throw()->json();
        $u = $res[0] ?? null;
        if (!$u) return null;
        return new UserProfile(
            id: (string) $u['id'],
            email: (string) ($u['email'] ?? ''),
            displayName: (string) (($u['firstName'] ?? '').' '.($u['lastName'] ?? '')),
            status: ($u['enabled'] ?? true) ? 'active' : 'inactive',
            attributes: ['raw' => $u],
        );
    }

    public function deactivate(string $id): void
    {
        $t = $this->adminToken();
        \Illuminate\Support\Facades\Http::withToken($t)
            ->put($this->adminBase().'/users/'.rawurlencode($id), [ 'enabled' => false ])
            ->throw();
    }

    public function activate(string $id): void
    {
        $t = $this->adminToken();
        \Illuminate\Support\Facades\Http::withToken($t)
            ->put($this->adminBase().'/users/'.rawurlencode($id), [ 'enabled' => true ])
            ->throw();
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // Typically front-end redirects to Keycloak account or reset page.
    }

    public function adminResetPassword(string $id): void
    {
        $t = $this->adminToken();
        \Illuminate\Support\Facades\Http::withToken($t)
            ->put($this->adminBase().'/users/'.rawurlencode($id).'/reset-password', [
                'type' => 'password',
                'value' => bin2hex(random_bytes(8)).'!Aa1',
                'temporary' => true,
            ])->throw();
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $t = $this->adminToken();
        $first = is_numeric($cursor ?? '') ? max(0, (int) $cursor) : 0;
        $params = [
            'first' => $first,
            'max' => max(1, min(200, $limit)),
        ];
        if ($query !== null && $query !== '') {
            $params['search'] = $query;
        }

        $res = \Illuminate\Support\Facades\Http::withToken($t)
            ->get($this->adminBase().'/users', $params)
            ->throw()->json();

        $items = [];
        foreach (($res ?? []) as $u) {
            if (!is_array($u)) continue;
            $items[] = new UserProfile(
                id: (string) ($u['id'] ?? ''),
                email: (string) ($u['email'] ?? ''),
                displayName: (string) ((($u['firstName'] ?? '')).' '.($u['lastName'] ?? '')),
                status: ($u['enabled'] ?? true) ? 'active' : 'inactive',
                attributes: ['raw' => $u],
            );
        }

        $nextCursor = (count($items) >= ($params['max'] ?? 50)) ? (string)($first + ($params['max'] ?? 50)) : null;
        return [ 'items' => $items, 'nextCursor' => $nextCursor ];
    }
}
