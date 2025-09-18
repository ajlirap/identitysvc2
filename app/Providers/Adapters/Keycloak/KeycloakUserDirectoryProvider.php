<?php

namespace App\Providers\Adapters\Keycloak;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;
use Illuminate\Support\Facades\Http;

class KeycloakUserDirectoryProvider implements UserDirectoryProvider
{
    private function adminBase(): string
    {
        $base = rtrim((string) config('identity.keycloak.base_url'), '/');
        $realm = rawurlencode((string) config('identity.keycloak.realm'));
        return $base . '/admin/realms/' . $realm;
    }

    private function adminToken(): string
    {
        $base = rtrim((string) config('identity.keycloak.base_url'), '/');
        $realm = rawurlencode((string) config('identity.keycloak.realm'));
        $resp = Http::asForm()
            ->post($base . '/realms/' . $realm . '/protocol/openid-connect/token', [
                'grant_type' => 'client_credentials',
                'client_id' => (string) config('identity.keycloak.client_id'),
                'client_secret' => (string) config('identity.keycloak.client_secret'),
            ])->throw()->json();
        return $resp['access_token'];
    }

    public function create(UserCreateRequest $req): UserProfile
    {
        $token = $this->adminToken();
        $body = [
            'enabled' => $req->isEnable,
            'username' => $req->email,
            'email' => $req->email,
            'firstName' => $req->firstName,
            'lastName' => $req->lastName,
            'emailVerified' => false,
            'attributes' => [
                'customerId' => [$req->customerId],
            ],
        ];

        $response = Http::withToken($token)
            ->post($this->adminBase() . '/users', $body)
            ->throw();

        $location = $response->header('Location');
        $id = $location ? basename($location) : '';

        return new UserProfile(
            id: $id,
            email: $req->email,
            givenName: $req->firstName,
            familyName: $req->lastName,
            displayName: trim(($req->firstName . ' ' . $req->lastName) ?: $req->email),
            status: $req->isEnable ? 'active' : 'inactive',
            roles: [],
            attributes: [
                'customerId' => $req->customerId,
                'location' => $location,
            ],
        );
    }

    public function findById(string $id): ?UserProfile
    {
        $token = $this->adminToken();
        $user = Http::withToken($token)
            ->get($this->adminBase() . '/users/' . rawurlencode($id))
            ->throw()->json();

        if (!$user || !isset($user['id'])) {
            return null;
        }

        return $this->mapUser($user);
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $token = $this->adminToken();
        $res = Http::withToken($token)
            ->get($this->adminBase() . '/users?email=' . rawurlencode($email))
            ->throw()->json();

        $user = $res[0] ?? null;
        if (!$user) {
            return null;
        }

        return $this->mapUser($user);
    }

    public function deactivate(string $id): void
    {
        $token = $this->adminToken();
        Http::withToken($token)
            ->put($this->adminBase() . '/users/' . rawurlencode($id), ['enabled' => false])
            ->throw();
    }

    public function activate(string $id): void
    {
        $token = $this->adminToken();
        Http::withToken($token)
            ->put($this->adminBase() . '/users/' . rawurlencode($id), ['enabled' => true])
            ->throw();
    }

    public function delete(string $id): void
    {
        $token = $this->adminToken();
        Http::withToken($token)
            ->delete($this->adminBase() . '/users/' . rawurlencode($id))
            ->throw();
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // Typically front-end redirects to Keycloak account or reset page.
    }

    public function adminResetPassword(string $id): void
    {
        $token = $this->adminToken();
        Http::withToken($token)
            ->put($this->adminBase() . '/users/' . rawurlencode($id) . '/reset-password', [
                'type' => 'password',
                'value' => bin2hex(random_bytes(8)) . '!Aa1',
                'temporary' => true,
            ])->throw();
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $token = $this->adminToken();
        $first = is_numeric($cursor ?? '') ? max(0, (int) $cursor) : 0;
        $params = [
            'first' => $first,
            'max' => max(1, min(200, $limit)),
        ];
        if ($query !== null && $query !== '') {
            $params['search'] = $query;
        }

        $res = Http::withToken($token)
            ->get($this->adminBase() . '/users', $params)
            ->throw()->json();

        $items = [];
        foreach (($res ?? []) as $user) {
            if (!is_array($user)) {
                continue;
            }
            $items[] = $this->mapUser($user);
        }

        $nextCursor = (count($items) >= ($params['max'] ?? 50)) ? (string) ($first + ($params['max'] ?? 50)) : null;
        return ['items' => $items, 'nextCursor' => $nextCursor];
    }

    private function mapUser(array $user): UserProfile
    {
        $attributes = (array) ($user['attributes'] ?? []);
        $firstName = (string) ($user['firstName'] ?? '');
        $lastName = (string) ($user['lastName'] ?? '');
        $email = (string) ($user['email'] ?? '');
        $enabled = (bool) ($user['enabled'] ?? true);

        return new UserProfile(
            id: (string) ($user['id'] ?? ''),
            email: $email,
            givenName: $firstName !== '' ? $firstName : null,
            familyName: $lastName !== '' ? $lastName : null,
            displayName: trim(($firstName . ' ' . $lastName) ?: $email),
            status: $enabled ? 'active' : 'inactive',
            roles: [],
            attributes: [
                'customerId' => $attributes['customerId'][0] ?? null,
                'raw' => $user,
            ],
        );
    }
}

