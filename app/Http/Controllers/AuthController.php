<?php

namespace App\Http\Controllers;

use App\Support\ProviderFactory;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;

class AuthController extends Controller
{
    /**
     * @OA\Get(
     *   path="/api/auth/login",
     *   summary="Start OIDC login",
     *   tags={"Auth"},
     *   @OA\Response(response=200, description="Authorize URL", @OA\JsonContent(type="object",
     *     @OA\Property(property="authorize_url", type="string")
     *   ))
     * )
     */
    public function login(Request $request)
    {
        $usePkce = $this->shouldUsePkce($request);

        $state = bin2hex(random_bytes(16));
        $extras = [
            'state' => $state,
            'nonce' => bin2hex(random_bytes(16)),
        ];

        if ($usePkce) {
            $verifier = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
            Cache::put('pkce:'.$state, $verifier, now()->addMinutes(10));
            $extras['code_challenge'] = $challenge;
        }

        $url = ProviderFactory::identity()->authorizeUrl($extras);
        return response()->json(['authorize_url' => $url]);
    }

    /**
     * @OA\Get(
     *   path="/api/auth/callback",
     *   summary="OIDC callback (auth code exchange)",
     *   tags={"Auth"},
     *   @OA\Parameter(name="code", in="query", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="state", in="query", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="Tokens")
     * )
     */
    public function callback(Request $request)
    {
        $code = (string) $request->string('code');
        $state = (string) $request->string('state');

        $verifier = (string) Cache::pull('pkce:'.$state, '');

        $tokens = ProviderFactory::identity()->exchangeCode($code, $verifier);
        return response()->json($tokens);
    }

    /**
     * @OA\Post(
     *   path="/api/auth/refresh",
     *   summary="Refresh tokens",
     *   tags={"Auth"},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object", required={"refresh_token"}, @OA\Property(property="refresh_token", type="string"))),
     *   @OA\Response(response=200, description="Tokens")
     * )
     */
    public function refresh(Request $request)
    {
        $refresh = (string) $request->string('refresh_token');
        $tokens = ProviderFactory::identity()->refresh($refresh);
        return response()->json($tokens);
    }

    /**
     * @OA\Get(
     *   path="/api/me",
     *   summary="Get current user profile",
     *   tags={"Auth"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Response(response=200, description="User profile"),
     *   @OA\Response(response=401, description="Unauthorized")
     * )
     */
    public function me(Request $request)
    {
        $access = $request->bearerToken();
        $profile = ProviderFactory::identity()->userInfo($access);
        return response()->json($profile);
    }

    /**
     * @OA\Post(
     *   path="/api/logout",
     *   summary="Logout (BFF/cleanup)",
     *   tags={"Auth"},
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function logout()
    {
        return response()->noContent();
    }

    private function shouldUsePkce(Request $request): bool
    {
        $vendor = (string) config('identity.vendor');
        $default = $vendor === 'b2c'
            ? (bool) config('identity.b2c.use_pkce', false)
            : true;

        if ($vendor !== 'b2c') {
            return $default;
        }

        $override = $this->parseNullableBoolean($request->input('pkce'));
        if ($override === null) {
            $override = $this->parseNullableBoolean($request->input('use_pkce'));
        }

        if ($override === null) {
            $clientType = $request->input('client_type', $request->input('flow'));
            if (is_string($clientType)) {
                $normalized = strtolower(trim($clientType));
                if (in_array($normalized, ['pkce', 'public', 'spa', 'native'], true)) {
                    $override = true;
                } elseif (in_array($normalized, ['confidential', 'server', 'backend'], true)) {
                    $override = false;
                }
            }
        }

        return $override ?? $default;
    }

    private function parseNullableBoolean($value): ?bool
    {
        if ($value === null) {
            return null;
        }

        if (is_bool($value)) {
            return $value;
        }

        if (is_int($value)) {
            return $value === 1;
        }

        if (is_numeric($value)) {
            $intValue = (int) $value;
            if ($intValue === 0 || $intValue === 1) {
                return $intValue === 1;
            }
        }

        if (is_string($value)) {
            $normalized = strtolower(trim($value));
            if ($normalized === '') {
                return null;
            }

            $truthy = ['true', '1', 'yes', 'on'];
            $falsy = ['false', '0', 'no', 'off'];

            if (in_array($normalized, $truthy, true)) {
                return true;
            }

            if (in_array($normalized, $falsy, true)) {
                return false;
            }
        }

        return null;
    }
}
