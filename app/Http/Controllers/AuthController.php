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
     *   description="Returns an authorization URL (and PKCE challenge when applicable) that the client can use to redirect the user to the upstream identity provider.",
     *   tags={"Auth"},
     *   @OA\Parameter(
     *     name="pkce",
     *     in="query",
     *     required=false,
     *     description="Explicitly enable or disable PKCE for this request (overrides default behavior).",
     *     @OA\Schema(type="boolean"),
     *     example=true
     *   ),
     *   @OA\Parameter(
     *     name="use_pkce",
     *     in="query",
     *     required=false,
     *     description="Alias for the pkce parameter.",
     *     @OA\Schema(type="boolean")
     *   ),
     *   @OA\Parameter(
     *     name="client_type",
     *     in="query",
     *     required=false,
     *     description="Hint used to infer PKCE behavior. Common values: 'spa', 'native', 'server'.",
     *     @OA\Schema(type="string"),
     *     example="spa"
     *   ),
     *   @OA\Response(
     *     response=200,
     *     description="Authorize URL payload",
     *     @OA\JsonContent(type="object",
     *       @OA\Property(property="authorize_url", type="string", example="https://login.identity.example.com/oauth2/v2.0/authorize?client_id=...&response_type=code&state=..."),
     *       @OA\Property(property="uses_pkce", type="boolean", example=true, description="Echo of the resolved PKCE decision for this request")
     *     )
     *   ),
     *   @OA\Response(response=429, ref="#/components/responses/TooManyRequests"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
            $verifier  = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
            $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
            Cache::put('pkce:' . $state, $verifier, now()->addMinutes(10));
            $extras['code_challenge'] = $challenge;
            // Optionally also pass code_challenge_method=S256 upstream if needed.
        }

        $url = ProviderFactory::identity()->authorizeUrl($extras);

        return response()->json([
            'authorize_url' => $url,
            'uses_pkce'     => $usePkce,
        ]);
    }

    /**
     * @OA\Get(
     *   path="/api/auth/callback",
     *   summary="OIDC callback (authorization code exchange)",
     *   description="Exchanges the authorization code for tokens. If PKCE was used for this 'state', the stored verifier is automatically applied.",
     *   tags={"Auth"},
     *   @OA\Parameter(name="code", in="query", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="state", in="query", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="OIDC token response", @OA\JsonContent(ref="#/components/schemas/Tokens")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=429, ref="#/components/responses/TooManyRequests"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function callback(Request $request)
    {
        $code   = (string) $request->string('code');
        $state  = (string) $request->string('state');

        $verifier = (string) Cache::pull('pkce:' . $state, '');

        $tokens = ProviderFactory::identity()->exchangeCode($code, $verifier);
        return response()->json($tokens);
    }

    /**
     * @OA\Post(
     *   path="/api/auth/refresh",
     *   summary="Refresh tokens",
     *   description="Use a refresh token to obtain a fresh access token (and optionally new refresh/id tokens).",
     *   tags={"Auth"},
     *   @OA\RequestBody(
     *     required=true,
  *     @OA\MediaType(
  *       mediaType="application/json",
  *       @OA\Schema(type="object",
  *         required={"refresh_token"},
  *         @OA\Property(property="refresh_token", type="string")
  *       )
  *     )
     *   ),
     *   @OA\Response(response=200, description="OIDC token response", @OA\JsonContent(ref="#/components/schemas/Tokens")),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=429, ref="#/components/responses/TooManyRequests"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function refresh(Request $request)
    {
        $refresh = (string) $request->string('refresh_token');
        $tokens  = ProviderFactory::identity()->refresh($refresh);
        return response()->json($tokens);
    }

    /**
     * @OA\Get(
     *   path="/api/me",
     *   summary="Get current user profile",
     *   description="Returns the normalized user profile for the bearer access token supplied in the Authorization header.",
     *   tags={"Auth"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Response(response=200, description="User profile", @OA\JsonContent(ref="#/components/schemas/UserProfile")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=429, ref="#/components/responses/TooManyRequests"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function me(Request $request)
    {
        $access  = $request->bearerToken();
        $profile = ProviderFactory::identity()->userInfo($access);
        return response()->json($profile);
    }

    /**
     * @OA\Post(
     *   path="/api/logout",
     *   summary="Logout",
     *   description="Performs local logout (stateless). Returns 204. The client should also sign out from the upstream identity provider if desired.",
     *   tags={"Auth"},
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=429, ref="#/components/responses/TooManyRequests"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function logout()
    {
        return response()->noContent();
    }

    // --- internal helpers (no annotations needed) ---

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
        if ($value === null) return null;
        if (is_bool($value)) return $value;
        if (is_int($value)) return $value === 1;

        if (is_numeric($value)) {
            $intValue = (int) $value;
            if ($intValue === 0 || $intValue === 1) return $intValue === 1;
        }

        if (is_string($value)) {
            $normalized = strtolower(trim($value));
            if ($normalized === '') return null;
            if (in_array($normalized, ['true', '1', 'yes', 'on'], true)) return true;
            if (in_array($normalized, ['false', '0', 'no', 'off'], true)) return false;
        }

        return null;
    }
}
