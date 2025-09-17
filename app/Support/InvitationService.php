<?php

namespace App\Support;

use App\DTO\UserProfile;
use Illuminate\Support\Facades\Http;

class InvitationService
{
    public static function sendInvite(UserProfile $user): array
    {
        $vendor = config('identity.vendor');
        return match ($vendor) {
            'auth0' => self::inviteAuth0($user),
            'okta' => self::inviteOkta($user),
            'keycloak' => self::inviteKeycloak($user),
            default => self::inviteB2C($user),
        };
    }

    private static function inviteAuth0(UserProfile $user): array
    {
        $domain = rtrim((string) config('identity.auth0.domain'), '/');
        $token = Http::asForm()->post("https://{$domain}/oauth/token", [
            'grant_type' => 'client_credentials',
            'client_id' => (string) config('identity.auth0.mgmt_client_id'),
            'client_secret' => (string) config('identity.auth0.mgmt_client_secret'),
            'audience' => (string) config('identity.auth0.mgmt_audience'),
        ])->throw()->json('access_token');

        $resp = Http::withToken($token)
            ->post("https://{$domain}/api/v2/tickets/password-change", [
                'user_id' => $user->id,
            ])->throw()->json();

        return ['ticket' => $resp['ticket'] ?? null];
    }

    private static function inviteOkta(UserProfile $user): array
    {
        $base = 'https://'.rtrim((string) config('identity.okta.domain'), '/');
        Http::withToken((string) config('identity.okta.api_token'))
            ->post($base.'/api/v1/users/'.rawurlencode($user->id).'/lifecycle/activate?sendEmail=true')
            ->throw();
        return ['emailSent' => true];
    }

    private static function inviteKeycloak(UserProfile $user): array
    {
        $base = rtrim((string) config('identity.keycloak.base_url'), '/');
        $realm = rawurlencode((string) config('identity.keycloak.realm'));
        $token = Http::asForm()->post($base.'/realms/'.$realm.'/protocol/openid-connect/token', [
            'grant_type' => 'client_credentials',
            'client_id' => (string) config('identity.keycloak.client_id'),
            'client_secret' => (string) config('identity.keycloak.client_secret'),
        ])->throw()->json('access_token');

        Http::withToken($token)
            ->post($base.'/admin/realms/'.$realm.'/users/'.rawurlencode($user->id).'/execute-actions-email', [
                'lifespan' => 3600,
                'redirectUri' => (string) config('identity.keycloak.redirect_uri'),
                'clientId' => (string) config('identity.keycloak.client_id'),
                'actions' => ['UPDATE_PASSWORD'],
            ])->throw();

        return ['emailSent' => true];
    }

    private static function inviteB2C(UserProfile $user): array
    {
        // Build password reset policy authorize URL as an invitation link
        $authorize = (string) config('identity.b2c.authorize_endpoint');
        $policy = (string) config('identity.b2c.policy_password_reset');
        $params = array_filter([
            'client_id' => (string) config('identity.b2c.client_id'),
            'response_type' => 'code',
            'redirect_uri' => (string) config('identity.b2c.redirect_uri'),
            'scope' => (string) config('identity.b2c.scope'),
            'response_mode' => 'query',
            'p' => $policy,
            'login_hint' => $user->email,
        ]);
        $url = rtrim($authorize, '?').'?'.http_build_query($params);
        return ['resetLink' => $url];
    }
}
