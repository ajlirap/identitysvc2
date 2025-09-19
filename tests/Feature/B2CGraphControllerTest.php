<?php

namespace Tests\Feature;

use App\Support\B2C\GraphClient;
use Illuminate\Support\Facades\Http;
use Tests\TestCase;

class B2CGraphControllerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('identity.vendor', 'b2c');
        config()->set('identity.b2c.enable_raw_routes', true);
    }

    public function test_openid_configuration_500_when_tenant_missing(): void
    {
        config()->set('identity.b2c.tenant', null);
        $this->getJson('/api/admin/b2c/openid-configuration')->assertStatus(500);
    }

    public function test_openid_configuration_returns_json(): void
    {
        config()->set('identity.b2c.tenant', 'contoso');
        Http::fake([
            'https://login.microsoftonline.com/*/.well-known/openid-configuration' => Http::response([
                'issuer' => 'https://login.microsoftonline.com/contoso',
                'token_endpoint' => 'https://login.microsoftonline.com/contoso/oauth2/v2.0/token',
                'jwks_uri' => 'https://login.microsoftonline.com/contoso/discovery/keys',
            ], 200),
        ]);
        $this->getJson('/api/admin/b2c/openid-configuration')
            ->assertOk()->assertJsonPath('issuer', 'https://login.microsoftonline.com/contoso');
    }

    public function test_patch_user_password_invokes_graph(): void
    {
        $spy = new class extends GraphClient {
            public array $calls = [];
            public function patch(string $url, array $body = []) { $this->calls[] = ['patch', $url, $body]; }
        };
        $this->app->instance(GraphClient::class, $spy);

        $payload = [ 'passwordProfile' => ['password' => 'NewPassword1', 'forceChangePasswordNextSignIn' => true] ];
        $this->patchJson('/api/admin/b2c/graph/users/u1/password', $payload)->assertNoContent();

        $this->assertNotEmpty($spy->calls);
        $this->assertSame('patch', $spy->calls[0][0]);
    }

    public function test_list_phone_methods_uses_http_fake(): void
    {
        // GraphClient::accessToken is used in controller method variants; fake token exchange + list call
        Http::fake([
            '*' => Http::response(['access_token' => 'tok'], 200),
        ]);

        // Force downstream list call to return a value payload
        Http::fake([
            'https://graph.microsoft.com/*/authentication/phoneMethods' => Http::response(['value' => [['id' => 'p1']]], 200),
        ]);

        $this->getJson('/api/admin/b2c/graph/users/u1/authentication/phoneMethods')
            ->assertOk()->assertJsonPath('value.0.id', 'p1');
    }
}

