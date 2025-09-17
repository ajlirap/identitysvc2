<?php

namespace App\Providers\Adapters\Okta;

use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;

class OktaUserDirectoryProvider implements UserDirectoryProvider
{
    private function base(): string
    {
        return 'https://'.rtrim((string) config('identity.okta.domain'), '/');
    }

    public function create(UserCreateRequest $req): UserProfile
    {
        $res = \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->post($this->base().'/api/v1/users?activate='.($req->invite ? 'false' : 'true'), [
                'profile' => [
                    'email' => $req->email,
                    'login' => $req->email,
                    'firstName' => $req->givenName,
                    'lastName' => $req->familyName,
                ],
                'credentials' => $req->invite ? null : [
                    'password' => [ 'value' => bin2hex(random_bytes(8)).'!Aa1' ],
                ],
            ])->throw()->json();

        return new UserProfile(
            id: (string) $res['id'],
            email: (string) $res['profile']['email'],
            displayName: (string) ($res['profile']['displayName'] ?? ($res['profile']['email'] ?? '')),
            status: $req->invite ? 'invited' : 'active',
            attributes: ['raw' => $res],
        );
    }

    public function findById(string $id): ?UserProfile
    {
        $res = \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->get($this->base().'/api/v1/users/'.rawurlencode($id))
            ->throw()->json();
        if (!$res || !isset($res['id'])) return null;
        return new UserProfile(
            id: (string) $res['id'],
            email: (string) ($res['profile']['email'] ?? ''),
            displayName: (string) ($res['profile']['displayName'] ?? ($res['profile']['email'] ?? '')),
            status: (($res['status'] ?? '') === 'DEPROVISIONED') ? 'inactive' : 'active',
            attributes: ['raw' => $res],
        );
    }

    public function findByEmail(string $email): ?UserProfile
    {
        $res = \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->get($this->base().'/api/v1/users?search='.rawurlencode('profile.email eq "'.$email.'"'))
            ->throw()->json();
        $u = $res[0] ?? null;
        if (!$u) return null;
        return new UserProfile(
            id: (string) $u['id'],
            email: (string) ($u['profile']['email'] ?? ''),
            displayName: (string) ($u['profile']['displayName'] ?? ($u['profile']['email'] ?? '')),
            status: (($u['status'] ?? '') === 'DEPROVISIONED') ? 'inactive' : 'active',
            attributes: ['raw' => $u],
        );
    }

    public function deactivate(string $id): void
    {
        \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->post($this->base().'/api/v1/users/'.rawurlencode($id).'/lifecycle/deactivate')
            ->throw();
    }

    public function activate(string $id): void
    {
        \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->post($this->base().'/api/v1/users/'.rawurlencode($id).'/lifecycle/activate?sendEmail=false')
            ->throw();
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // Typically front-end redirects to Okta hosted reset page.
    }

    public function adminResetPassword(string $id): void
    {
        \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->post($this->base().'/api/v1/users/'.rawurlencode($id).'/lifecycle/reset_password?sendEmail=true')
            ->throw();
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $params = [ 'limit' => max(1, min(200, $limit)) ];
        if ($query !== null && $query !== '') {
            // Okta supports simple q search across profile fields
            $params['q'] = $query;
        }
        if ($cursor) {
            $params['after'] = $cursor;
        }

        $resp = \Illuminate\Support\Facades\Http::withHeaders([
                'Accept' => 'application/json',
                'Authorization' => 'SSWS '.(string) config('identity.okta.api_token'),
            ])
            ->get($this->base().'/api/v1/users', $params)
            ->throw();

        $data = $resp->json();
        $items = [];
        foreach (($data ?? []) as $u) {
            if (!is_array($u)) continue;
            $items[] = new UserProfile(
                id: (string) ($u['id'] ?? ''),
                email: (string) ($u['profile']['email'] ?? ''),
                displayName: (string) ($u['profile']['displayName'] ?? ($u['profile']['email'] ?? '')),
                status: (($u['status'] ?? '') === 'DEPROVISIONED') ? 'inactive' : 'active',
                attributes: ['raw' => $u],
            );
        }

        $link = (string) ($resp->header('Link') ?? '');
        $nextCursor = null;
        if ($link && str_contains($link, 'rel="next"')) {
            // Parse after token from next link
            // Example: <https://.../api/v1/users?after=abc&limit=50>; rel="next"
            if (preg_match('/<[^>]*after=([^&>]+)[^>]*>\\s*;\\s*rel="next"/i', $link, $m)) {
                $nextCursor = $m[1] ?? null;
            }
        }

        return [ 'items' => $items, 'nextCursor' => $nextCursor ];
    }
}
