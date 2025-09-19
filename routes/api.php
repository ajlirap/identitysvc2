<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\B2CGraphController;
use App\Http\Controllers\UsersController;
use App\Http\Middleware\VerifyJwt;
use Illuminate\Support\Facades\Route;

// Public auth façade
Route::get('/auth/login', [AuthController::class, 'login']);
Route::get('/auth/callback', [AuthController::class, 'callback']);
Route::post('/auth/refresh', [AuthController::class, 'refresh']);
Route::get('/me', [AuthController::class, 'me'])->middleware(VerifyJwt::class);
Route::post('/logout', [AuthController::class, 'logout']);

// User lifecycle (protect with your admin auth e.g., mTLS or internal auth)
Route::prefix('admin')->group(function () {
    if ((string) config('identity.vendor') === 'b2c' && (bool) config('identity.b2c.enable_raw_routes')) {
        Route::get('/b2c/openid-configuration', [B2CGraphController::class, 'openidConfiguration']);
        Route::post('/b2c/graph/token', [B2CGraphController::class, 'token']);
        Route::get('/b2c/graph/users/{id}', [B2CGraphController::class, 'graphUserById']);
        Route::get('/b2c/graph/users', [B2CGraphController::class, 'graphUsersByMail']);
        Route::patch('/b2c/graph/users/{id}', [B2CGraphController::class, 'patchGraphUser']);
        Route::patch('/b2c/graph/users/{id}/identities', [B2CGraphController::class, 'patchGraphUserIdentities']);
        Route::patch('/b2c/graph/users/{id}/email-identity', [B2CGraphController::class, 'patchGraphUserEmailIdentity']);
        Route::patch('/b2c/graph/users/{id}/password', [B2CGraphController::class, 'patchGraphUserPassword']);
        Route::delete('/b2c/graph/users/{id}', [B2CGraphController::class, 'deleteGraphUser']);
        Route::post('/b2c/graph/users', [B2CGraphController::class, 'createGraphUser']);
        Route::post('/b2c/graph/me/items/{id}/workbook/closeSession', [B2CGraphController::class, 'closeWorkbookSession']);
        Route::get('/b2c/graph/users/{id}/authentication/phoneMethods', [B2CGraphController::class, 'listPhoneMethods']);
        Route::post('/b2c/graph/users/{id}/authentication/phoneMethods', [B2CGraphController::class, 'addPhoneMethod']);
        Route::delete('/b2c/graph/users/{id}/authentication/phoneMethods', [B2CGraphController::class, 'deletePhoneMethods']);
        Route::get('/b2c/graph/users/{id}/authentication/emailMethods', [B2CGraphController::class, 'listEmailMethods']);
        Route::post('/b2c/graph/users/{id}/authentication/emailMethods', [B2CGraphController::class, 'addEmailMethod']);
        Route::delete('/b2c/graph/users/{id}/authentication/emailMethods', [B2CGraphController::class, 'deleteEmailMethods']);
        Route::get('/b2c/graph/users/{id}/authentication/methods', [B2CGraphController::class, 'listAuthMethods']);
        Route::post('/b2c/graph/users/{id}/authentication/methods/{methodId}/resetPassword', [B2CGraphController::class, 'resetPassword']);
    }
    Route::get('/users', [UsersController::class, 'index']);
    Route::post('/users', [UsersController::class, 'create']);
    // Place fixed routes before parameterized ones to avoid conflicts
    Route::get('/users/by-email', [UsersController::class, 'getByEmail']);
    Route::get('/users/{id}', [UsersController::class, 'get']);
    Route::delete('/users/{id}', [UsersController::class, 'delete']);
    Route::post('/users/{id}/deactivate', [UsersController::class, 'deactivate']);
    Route::post('/users/{id}/activate', [UsersController::class, 'activate']);
    Route::post('/users/{id}/password-reset', [UsersController::class, 'adminReset']);
    Route::patch('/users/{id}/password', [UsersController::class, 'updatePasswordProfile']);
    Route::patch('/users/{id}/email-identity', [UsersController::class, 'updateEmailIdentity']);
    Route::patch('/users/{id}/identities', [UsersController::class, 'updateIdentities']);
    Route::get('/users/{id}/authentication/phone-methods', [UsersController::class, 'listPhoneMethods']);
    Route::post('/users/{id}/authentication/phone-methods', [UsersController::class, 'addPhoneMethod']);
    Route::delete('/users/{id}/authentication/phone-methods', [UsersController::class, 'deletePhoneMethods']);
    Route::get('/users/{id}/authentication/email-methods', [UsersController::class, 'listEmailMethods']);
    Route::post('/users/{id}/authentication/email-methods', [UsersController::class, 'addEmailMethod']);
    Route::delete('/users/{id}/authentication/email-methods', [UsersController::class, 'deleteEmailMethods']);
    Route::get('/users/{id}/authentication/methods', [UsersController::class, 'listAuthMethods']);
    Route::post('/users/{id}/authentication/methods/{methodId}/reset-password', [UsersController::class, 'resetAuthMethodPassword']);
    Route::post('/users/invite', [UsersController::class, 'invite']);
    // Admin-safe existence/active check (JWT guarded)
    Route::post('/users/check-active', [UsersController::class, 'adminCheckActive'])->middleware(VerifyJwt::class);
});
