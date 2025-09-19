<?php

namespace Tests\Feature;

use App\Contracts\IdentityProvider;
use App\DTO\Tokens;
use App\DTO\UserProfile;
use App\Providers\Adapters\B2C\B2CIdentityProvider;
use App\Security\JwtValidator;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

class AuthControllerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('identity.vendor', 'b2c');

        // Bind a fake IdentityProvider so ProviderFactory::identity() resolves it
        $idp = \Mockery::mock(IdentityProvider::class);
        // Alias to the concrete that ProviderFactory resolves for b2c
        $this->app->instance(B2CIdentityProvider::class, $idp);
    }

    public function test_login_pkce_query_override_true(): void
    {
        /** @var IdentityProvider $idp */
        $idp = $this->app->make(B2CIdentityProvider::class);

        $idp->shouldReceive('authorizeUrl')
            ->once()
            ->withArgs(function (array $extras) {
                // state, nonce always present; if PKCE, code_challenge is set
                return isset($extras['state'], $extras['nonce'], $extras['code_challenge']);
            })
            ->andReturn('https://example.test/authorize');

        $res = $this->getJson('/api/auth/login?pkce=1');

        $res->assertOk()
            ->assertJsonPath('authorize_url', 'https://example.test/authorize')
            ->assertJsonPath('uses_pkce', true);
    }

    public function test_login_client_type_server_disables_pkce(): void
    {
        /** @var IdentityProvider $idp */
        $idp = $this->app->make(B2CIdentityProvider::class);

        $idp->shouldReceive('authorizeUrl')
            ->once()
            ->withArgs(function (array $extras) {
                // No PKCE challenge expected when client_type=server
                return isset($extras['state'], $extras['nonce']) && !isset($extras['code_challenge']);
            })
            ->andReturn('https://example.test/authorize');

        $res = $this->getJson('/api/auth/login?client_type=server');

        $res->assertOk()->assertJsonPath('uses_pkce', false);
    }

    public function test_callback_applies_cached_pkce_verifier(): void
    {
        /** @var IdentityProvider $idp */
        $idp = $this->app->make(B2CIdentityProvider::class);

        $state = 'abc123state';
        Cache::put('pkce:' . $state, 'verifierXYZ', now()->addMinutes(5));

        $tokens = new Tokens(accessToken: 'acc', refreshToken: 'ref', expiresIn: 3600, idToken: 'id');
        $idp->shouldReceive('exchangeCode')
            ->once()
            ->with('theCode', 'verifierXYZ')
            ->andReturn($tokens);

        $res = $this->getJson('/api/auth/callback?code=theCode&state=' . $state);

        $res->assertOk()->assertJsonPath('accessToken', 'acc');
    }

    public function test_refresh_uses_provider(): void
    {
        /** @var IdentityProvider $idp */
        $idp = $this->app->make(B2CIdentityProvider::class);
        $idp->shouldReceive('refresh')
            ->once()
            ->with('r123')
            ->andReturn(new Tokens(accessToken: 'a2', refreshToken: 'r2', expiresIn: 3600));

        $res = $this->postJson('/api/auth/refresh', ['refresh_token' => 'r123']);

        $res->assertOk()->assertJsonPath('refreshToken', 'r2');
    }

    public function test_me_returns_profile_with_valid_jwt(): void
    {
        // Mock JwtValidator to bypass real signature checking
        $validator = \Mockery::mock(JwtValidator::class);
        $validator->shouldReceive('validate')->andReturn(['sub' => 'user1']);
        $this->app->instance(JwtValidator::class, $validator);

        /** @var IdentityProvider $idp */
        $idp = $this->app->make(B2CIdentityProvider::class);
        $idp->shouldReceive('issuer')->andReturn('https://issuer.test');
        $idp->shouldReceive('jwksUri')->andReturn('https://issuer.test/jwks');
        $idp->shouldReceive('userInfo')->once()->with('BearerTokenHere')->andReturn(
            new UserProfile(id: 'u1', email: 'user@example.com', status: 'active')
        );

        $res = $this->getJson('/api/me', [
            'Authorization' => 'Bearer BearerTokenHere',
        ]);

        $res->assertOk()->assertJsonPath('email', 'user@example.com');
    }

    public function test_logout_no_content(): void
    {
        $this->postJson('/api/logout')->assertNoContent();
    }
}
