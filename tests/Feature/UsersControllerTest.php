<?php

namespace Tests\Feature;

use App\Contracts\SupportsUserAuthenticationMethods;
use App\Contracts\SupportsUserIdentityManagement;
use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;
use App\Providers\Adapters\B2C\B2CUserDirectoryProvider;
use App\Security\CaptchaVerifier;
use App\Security\JwtValidator;
use Tests\TestCase;

class UsersControllerTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        config()->set('identity.vendor', 'b2c');

        // Default: directory provider mock
        $dir = \Mockery::mock(UserDirectoryProvider::class);
        $this->app->instance(B2CUserDirectoryProvider::class, $dir);

        // Bind a minimal IDP for middleware metadata lookups in VerifyJwt
        $idp = \Mockery::mock(\App\Contracts\IdentityProvider::class);
        $idp->shouldReceive('issuer')->andReturn('https://issuer.test');
        $idp->shouldReceive('jwksUri')->andReturn('https://issuer.test/jwks');
        $this->app->instance(\App\Providers\Adapters\B2C\B2CIdentityProvider::class, $idp);

        // Disable captcha by default in tests
        config()->set('identity.captcha.enabled', false);
        $this->app->instance(CaptchaVerifier::class, new class {
            public function enabled(): bool { return false; }
            public function verify(?string $t, ?string $ip = null): bool { return true; }
        });
    }

    public function test_index_lists_users(): void
    {
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        $dir->shouldReceive('listUsers')->once()->with(null, 50, null)->andReturn([
            'items' => [ new UserProfile(id: '1', email: 'a@e.com') ],
            'nextCursor' => null,
        ]);
        $this->getJson('/api/admin/users')->assertOk()->assertJsonPath('items.0.id', '1');
    }

    public function test_create_user_returns_201(): void
    {
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        $dir->shouldReceive('create')
            ->once()
            ->withArgs(function (UserCreateRequest $req) { return $req->email === 'new@example.com'; })
            ->andReturn(new UserProfile(id: 'u123', email: 'new@example.com'));

        $payload = [
            'customerId' => 'c1',
            'firstName' => 'First',
            'lastName' => 'Last',
            'email' => 'new@example.com',
            'isEnable' => true,
            // include password to match current controller access of ['password']
            'password' => 'TempPassw0rd!',
        ];
        $this->postJson('/api/admin/users', $payload)
            ->assertCreated()
            ->assertJsonPath('id', 'u123');
    }

    public function test_get_user_not_found_and_found(): void
    {
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        $dir->shouldReceive('findById')->once()->with('nope')->andReturn(null);
        $this->getJson('/api/admin/users/nope')->assertNotFound();

        $dir->shouldReceive('findById')->once()->with('u1')->andReturn(new UserProfile(id: 'u1', email: 'e@example.com'));
        $this->getJson('/api/admin/users/u1')->assertOk()->assertJsonPath('email', 'e@example.com');
    }

    public function test_get_user_by_email_not_found_and_found(): void
    {
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        // Not found
        $dir->shouldReceive('findByEmail')->once()->with('none@example.com')->andReturn(null);
        $this->getJson('/api/admin/users/by-email?email=none@example.com')->assertNotFound();

        // Found
        $dir->shouldReceive('findByEmail')->once()->with('got@example.com')->andReturn(new UserProfile(id: 'u2', email: 'got@example.com'));
        $this->getJson('/api/admin/users/by-email?email=got@example.com')->assertOk()->assertJsonPath('id', 'u2');

        // Invalid email -> 400
        $this->getJson('/api/admin/users/by-email?email=bad')->assertStatus(400);
    }

    public function test_activate_deactivate_delete_adminReset_no_content(): void
    {
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        $dir->shouldReceive('deactivate')->once()->with('u1');
        $this->postJson('/api/admin/users/u1/deactivate')->assertNoContent();

        $dir->shouldReceive('activate')->once()->with('u1');
        $this->postJson('/api/admin/users/u1/activate')->assertNoContent();

        $dir->shouldReceive('adminResetPassword')->once()->with('u1');
        $this->postJson('/api/admin/users/u1/password-reset', ['newPassword' => 'NewPassword1'])->assertNoContent();

        $dir->shouldReceive('delete')->once()->with('u1');
        $this->deleteJson('/api/admin/users/u1')->assertNoContent();
    }

    // startPasswordReset public endpoint removed

    public function test_identity_management_unsupported_returns_501(): void
    {
        // Directory does NOT implement SupportsUserIdentityManagement
        $payload = [ 'passwordProfile' => ['password' => 'NewPassword1', 'forceChangePasswordNextSignIn' => true] ];
        $this->patchJson('/api/admin/users/u1/password', $payload)
            ->assertStatus(501)
            ->assertJsonPath('capability', 'user_identity_management');
    }

    public function test_identity_management_supported_paths(): void
    {
        // Replace binding with a mock that implements SupportsUserIdentityManagement
        $mock = \Mockery::mock(UserDirectoryProvider::class, SupportsUserIdentityManagement::class);
        $mock->shouldReceive('updatePasswordProfile')->once();
        $mock->shouldReceive('updateEmailIdentities')->once();
        $mock->shouldReceive('updateIdentities')->once();
        $this->app->instance(B2CUserDirectoryProvider::class, $mock);

        $this->patchJson('/api/admin/users/u1/password', [
            'passwordProfile' => ['password' => 'NewPassword1', 'forceChangePasswordNextSignIn' => true],
        ])->assertNoContent();

        $this->patchJson('/api/admin/users/u1/email-identity', [
            'identities' => [[ 'signInType' => 'emailAddress', 'issuer' => 'contoso', 'issuerAssignedId' => 'a@b.com' ]],
        ])->assertNoContent();

        $this->patchJson('/api/admin/users/u1/identities', [
            'mail' => 'a@b.com',
            'identities' => [[ 'signInType' => 'emailAddress', 'issuer' => 'contoso', 'issuerAssignedId' => 'a@b.com' ]],
            'passwordProfile' => ['password' => 'NewPassword1', 'forceChangePasswordNextSignIn' => true],
        ])->assertNoContent();
    }

    public function test_auth_methods_unsupported_returns_501(): void
    {
        $this->getJson('/api/admin/users/u1/authentication/phone-methods')->assertStatus(501);
        $this->postJson('/api/admin/users/u1/authentication/phone-methods', ['phoneNumber' => '1', 'phoneType' => 'mobile'])->assertStatus(501);
        $this->deleteJson('/api/admin/users/u1/authentication/phone-methods')->assertStatus(501);
    }

    public function test_auth_methods_supported_flow(): void
    {
        $mock = \Mockery::mock(UserDirectoryProvider::class, SupportsUserAuthenticationMethods::class);
        $mock->shouldReceive('listPhoneMethods')->once()->andReturn([['id' => 'p1']]);
        $mock->shouldReceive('addPhoneMethod')->once()->andReturn(['id' => 'p2']);
        $mock->shouldReceive('deletePhoneMethods')->once();
        $mock->shouldReceive('listEmailMethods')->once()->andReturn([['id' => 'e1']]);
        $mock->shouldReceive('addEmailMethod')->once()->andReturn(['id' => 'e2']);
        $mock->shouldReceive('deleteEmailMethods')->once();
        $mock->shouldReceive('listAuthenticationMethods')->once()->andReturn([['id' => 'm1']]);
        $mock->shouldReceive('resetAuthenticationMethodPassword')->once()->andReturn(['status' => 'ok']);
        $this->app->instance(B2CUserDirectoryProvider::class, $mock);

        $this->getJson('/api/admin/users/u1/authentication/phone-methods')->assertOk()->assertJsonFragment(['id' => 'p1']);
        $this->postJson('/api/admin/users/u1/authentication/phone-methods', ['phoneNumber' => '123', 'phoneType' => 'mobile'])->assertCreated();
        $this->deleteJson('/api/admin/users/u1/authentication/phone-methods')->assertNoContent();

        $this->getJson('/api/admin/users/u1/authentication/email-methods')->assertOk()->assertJsonFragment(['id' => 'e1']);
        $this->postJson('/api/admin/users/u1/authentication/email-methods', ['emailAddress' => 'x@y.com'])->assertCreated();
        $this->deleteJson('/api/admin/users/u1/authentication/email-methods')->assertNoContent();

        $this->getJson('/api/admin/users/u1/authentication/methods')->assertOk()->assertJsonFragment(['id' => 'm1']);
        $this->postJson('/api/admin/users/u1/authentication/methods/m123/reset-password', ['newPassword' => 'NewPassword1'])
            ->assertOk()->assertJsonPath('status', 'ok');
    }

    public function test_validate_email_with_captcha_failure(): void
    {
        // Enable captcha and force verify to fail
        config()->set('identity.captcha.enabled', true);
        $this->app->instance(CaptchaVerifier::class, new class {
            public function enabled(): bool { return true; }
            public function verify(?string $t, ?string $ip = null): bool { return false; }
        });

        $this->postJson('/api/users/validate-email', ['email' => 'x@y.com', 'captcha' => 'bad'])
            ->assertStatus(400)
            ->assertJsonPath('message', 'captcha_failed');
    }

    public function test_check_active_public_paths(): void
    {
        // reveal_existence=false: no enumeration, skip provider call
        config()->set('identity.email_validation.reveal_existence', false);
        $this->postJson('/api/users/check-active', ['email' => 'x@y.com'])
            ->assertOk()
            ->assertJsonMissingPath('exists')
            ->assertJsonMissingPath('active');

        // reveal_existence=true: calls provider->findByEmail and reveals exists/active
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        $dir->shouldReceive('findByEmail')->once()->with('x@y.com')->andReturn(new UserProfile(id: 'u9', email: 'x@y.com', status: 'active'));
        config()->set('identity.email_validation.reveal_existence', true);
        $this->postJson('/api/users/check-active', ['email' => 'x@y.com'])
            ->assertOk()->assertJsonPath('exists', true)->assertJsonPath('active', true);
    }

    public function test_admin_check_active_requires_admin_role_and_valid_email(): void
    {
        // Invalid email -> 400 (supply Authorization to pass middleware)
        $validator = \Mockery::mock(JwtValidator::class);
        $validator->shouldReceive('validate')->andReturn(['roles' => []]);
        $this->app->instance(JwtValidator::class, $validator);
        $this->postJson('/api/admin/users/check-active', ['email' => 'bad'], ['Authorization' => 'Bearer t'])
            ->assertStatus(400);

        // Mock JwtValidator and IDP metadata
        // Authorization header but no admin role -> 403
        $validator = \Mockery::mock(JwtValidator::class);
        $validator->shouldReceive('validate')->andReturn(['roles' => []]);
        $this->app->instance(JwtValidator::class, $validator);
        $this->postJson('/api/admin/users/check-active', ['email' => 'a@b.com'], [ 'Authorization' => 'Bearer t' ])->assertStatus(403);

        // With admin role -> 200 and payload
        $validator = \Mockery::mock(JwtValidator::class);
        $validator->shouldReceive('validate')->andReturn(['roles' => ['idp.admin']]);
        $this->app->instance(JwtValidator::class, $validator);
        /** @var UserDirectoryProvider $dir */
        $dir = $this->app->make(B2CUserDirectoryProvider::class);
        $dir->shouldReceive('findByEmail')->once()->with('a@b.com')->andReturn(new UserProfile(id: 'u1', email: 'a@b.com', status: 'inactive'));

        $this->postJson('/api/admin/users/check-active', ['email' => 'a@b.com'], [ 'Authorization' => 'Bearer t' ])
            ->assertOk()
            ->assertJsonPath('exists', true)
            ->assertJsonPath('active', false)
            ->assertJsonPath('user.email', 'a@b.com');
    }
}
