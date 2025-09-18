<?php

namespace App\Providers\Adapters\Auth0;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;
use Illuminate\Support\Facades\Http;

class Auth0UserDirectoryProvider implements UserDirectoryProvider
{
    private function mgmtToken(): string
    {
        $domain = rtrim((string) config('identity.auth0.domain'), '/');
        $resp = Http::asForm()
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
        $token = $this->mgmtToken();
        $email = mb_strtolower($req->email);
        $name = trim(($req->firstName . ' ' . $req->lastName) ?: $email);

        $payload = [
            'email' => $email,
            'name' => $name,
            'given_name' => $req->firstName,
            'family_name' => $req->lastName,
            'connection' => 'Username-Password-Authentication',
            'verify_email' => false,
            'blocked' => !$req->isEnable,
            'user_metadata' => [
                'customerId' => $req->customerId,
            ],
            'password' => bin2hex(random_bytes(8)) . '!Aa1',
        ];

        $res = Http::withToken($token)
            ->post('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users', $payload)
            ->throw()->json();

        return $this->mapUser($res);
    }

    public function findById(string $id): ?UserProfile
    {
        $token = $this->mgmtToken();
        $res = Http::withToken($token)
            ->get('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users/' . rawurlencode($id))
            ->throw()->json();

        if (!$res || !isset($res['user_id'])) {
            return null;
        }

        return $this->mapUser($res);
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $token = $this->mgmtToken();
        $res = Http::withToken($token)
            ->get('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users-by-email?email=' . rawurlencode($email))
            ->throw()->json();

        $user = $res[0] ?? null;
        if (!$user) {
            return null;
        }

        return $this->mapUser($user);
    }

    public function deactivate(string $id): void
    {
        $token = $this->mgmtToken();
        Http::withToken($token)
            ->patch('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users/' . rawurlencode($id), [
                'blocked' => true,
            ])->throw();
    }

    public function activate(string $id): void
    {
        $token = $this->mgmtToken();
        Http::withToken($token)
            ->patch('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users/' . rawurlencode($id), [
                'blocked' => false,
            ])->throw();
    }

    public function delete(string $id): void
    {
        $token = $this->mgmtToken();
        Http::withToken($token)
            ->delete('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users/' . rawurlencode($id))
            ->throw();
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // Typically front-end redirects to /u/reset-password hosted page.
    }

    public function adminResetPassword(string $id): void
    {
        $token = $this->mgmtToken();
        Http::withToken($token)
            ->post('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/tickets/password-change', [
                'user_id' => $id,
            ])->throw();
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $token = $this->mgmtToken();
        $page = is_numeric($cursor ?? '') ? (int) $cursor : 0;
        $params = [
            'per_page' => max(1, min(100, $limit)),
            'page' => max(0, $page),
        ];
        if ($query !== null && $query !== '') {
            $params['q'] = $query;
            $params['search_engine'] = 'v3';
        }

        $res = Http::withToken($token)
            ->get('https://' . rtrim((string) config('identity.auth0.domain'), '/') . '/api/v2/users', $params)
            ->throw()->json();

        $items = [];
        foreach (($res ?? []) as $user) {
            if (!is_array($user)) {
                continue;
            }
            $items[] = $this->mapUser($user);
        }

        $nextCursor = (count($items) >= ($params['per_page'] ?? 50)) ? (string) ($page + 1) : null;
        return ['items' => $items, 'nextCursor' => $nextCursor];
    }

    private function mapUser(array $data): UserProfile
    {
        $email = (string) ($data['email'] ?? '');
        $given = (string) ($data['given_name'] ?? null);
        $family = (string) ($data['family_name'] ?? null);
        $name = (string) ($data['name'] ?? trim(($given . ' ' . $family) ?: $email));
        $blocked = (bool) ($data['blocked'] ?? false);
        $metadata = (array) ($data['user_metadata'] ?? []);

        return new UserProfile(
            id: (string) ($data['user_id'] ?? ''),
            email: $email,
            givenName: $given !== '' ? $given : null,
            familyName: $family !== '' ? $family : null,
            displayName: $name,
            status: $blocked ? 'inactive' : 'active',
            roles: [],
            attributes: [
                'customerId' => $metadata['customerId'] ?? null,
                'raw' => $data,
            ],
        );
    }
}

