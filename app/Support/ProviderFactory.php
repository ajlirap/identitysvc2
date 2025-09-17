<?php

namespace App\Support;

use App\Contracts\IdentityProvider;
use App\Contracts\UserDirectoryProvider;
use App\Providers\Adapters\B2C\B2CIdentityProvider;
use App\Providers\Adapters\B2C\B2CUserDirectoryProvider;
use App\Providers\Adapters\Auth0\Auth0IdentityProvider;
use App\Providers\Adapters\Auth0\Auth0UserDirectoryProvider;
use App\Providers\Adapters\Okta\OktaIdentityProvider;
use App\Providers\Adapters\Okta\OktaUserDirectoryProvider;
use App\Providers\Adapters\Keycloak\KeycloakIdentityProvider;
use App\Providers\Adapters\Keycloak\KeycloakUserDirectoryProvider;

class ProviderFactory
{
    public static function identity(): IdentityProvider
    {
        return match (config('identity.vendor')) {
            'auth0' => app(Auth0IdentityProvider::class),
            'okta' => app(OktaIdentityProvider::class),
            'keycloak' => app(KeycloakIdentityProvider::class),
            default => app(B2CIdentityProvider::class),
        };
    }

    public static function directory(): UserDirectoryProvider
    {
        return match (config('identity.vendor')) {
            'auth0' => app(Auth0UserDirectoryProvider::class),
            'okta' => app(OktaUserDirectoryProvider::class),
            'keycloak' => app(KeycloakUserDirectoryProvider::class),
            default => app(B2CUserDirectoryProvider::class),
        };
    }
}

