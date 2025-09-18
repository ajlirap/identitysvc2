<?php

namespace App\Providers\Adapters\Okta;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;
use Illuminate\Support\Facades\Http;

class OktaUserDirectoryProvider implements UserDirectoryProvider
{
    private function base(): string
    {
        return 'https://' . rtrim((string) config('identity.okta.domain'), '/');
    }

    public function create(UserCreateRequest $req): UserProfile
    {
        $body = [
            'profile' => [
                'email' => $req->email,
                'login' => $req->email,
                'firstName' => $req->firstName,
                'lastName' => $req->lastName,
                'customerId' => $req->customerId,
            ],
        ];

        if ($req->isEnable) {
            $activate = 'true';
            $body['credentials'] = [
                'password' => ['value' => bin2hex(random_bytes(8)) . '!Aa1'],
            ];
        } else {
            $activate = 'false';
        }

        $res = Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->post($this->base() . '/api/v1/users?activate=' . $activate, $body)
            ->throw()->json();

        return $this->mapUser($res);
    }

    public function findById(string $id): ?UserProfile
    {
        $res = Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->get($this->base() . '/api/v1/users/' . rawurlencode($id))
            ->throw()->json();

        if (!$res || !isset($res['id'])) {
            return null;
        }

        return $this->mapUser($res);
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $res = Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->get($this->base() . '/api/v1/users?search=' . rawurlencode('profile.email eq "' . $email . '"'))
            ->throw()->json();

        $user = $res[0] ?? null;
        if (!$user) {
            return null;
        }

        return $this->mapUser($user);
    }

    public function deactivate(string $id): void
    {
        Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->post($this->base() . '/api/v1/users/' . rawurlencode($id) . '/lifecycle/deactivate')
            ->throw();
    }

    public function activate(string $id): void
    {
        Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->post($this->base() . '/api/v1/users/' . rawurlencode($id) . '/lifecycle/activate?sendEmail=false')
            ->throw();
    }

    public function delete(string $id): void
    {
        Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->delete($this->base() . '/api/v1/users/' . rawurlencode($id))
            ->throw();
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // Typically front-end redirects to Okta hosted reset page.
    }

    public function adminResetPassword(string $id): void
    {
        Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->post($this->base() . '/api/v1/users/' . rawurlencode($id) . '/lifecycle/reset_password?sendEmail=true')
            ->throw();
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $params = ['limit' => max(1, min(200, $limit))];
        if ($query !== null && $query !== '') {
            $params['q'] = $query;
        }
        if ($cursor) {
            $params['after'] = $cursor;
        }

        $resp = Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS ' . (string) config('identity.okta.api_token'),
            ])
            ->get($this->base() . '/api/v1/users', $params)
            ->throw();

        $data = $resp->json();
        $items = [];
        foreach (($data ?? []) as $user) {
            if (!is_array($user)) {
                continue;
            }
            $items[] = $this->mapUser($user);
        }

        $link = (string) ($resp->header('Link') ?? '');
        $nextCursor = null;
        if ($link && str_contains($link, 'rel="next"')) {
            if (preg_match('/<[^>]*after=([^&>]+)[^>]*>\s*;\s*rel="next"/i', $link, $matches)) {
                $nextCursor = $matches[1] ?? null;
            }
        }

        return ['items' => $items, 'nextCursor' => $nextCursor];
    }

    private function mapUser(array $data): UserProfile
    {
        $profile = (array) ($data['profile'] ?? []);
        $status = (string) ($data['status'] ?? '');
        $email = (string) ($profile['email'] ?? '');
        $displayName = (string) ($profile['displayName'] ?? trim((($profile['firstName'] ?? '') . ' ' . ($profile['lastName'] ?? '')) ?: $email));

        return new UserProfile(
            id: (string) ($data['id'] ?? ''),
            email: $email,
            givenName: (string) ($profile['firstName'] ?? null),
            familyName: (string) ($profile['lastName'] ?? null),
            displayName: $displayName,
            status: ($status === 'DEPROVISIONED' || $status === 'SUSPENDED') ? 'inactive' : 'active',
            roles: [],
            attributes: [
                'customerId' => $profile['customerId'] ?? null,
                'raw' => $data,
            ],
        );
    }
}

