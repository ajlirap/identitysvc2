<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
use App\Support\B2C\GraphClient;

class B2CGraphController extends Controller
{
    public function __construct(private readonly GraphClient $graph)
    {
    }

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/openid-configuration",
     *   summary="Get OpenID configuration for the tenant",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Response(
     *     response=200,
     *     description="OIDC discovery document"
     *   )
     * )
     */
    public function openidConfiguration()
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        abort_if($tenant === '', 500, 'Tenant not configured');

        $url = "https://login.microsoftonline.com/{$tenant}/.well-known/openid-configuration";
        $resp = Http::get($url)->throw();
        return response()->json($resp->json());
    }

    private function discoverTokenEndpoint(): string
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        if ($tenant === '') return '';
        try {
            $url = "https://login.microsoftonline.com/{$tenant}/.well-known/openid-configuration";
            $conf = Http::get($url)->throw()->json();
            return (string) ($conf['token_endpoint'] ?? '');
        } catch (\Throwable $e) {
            return '';
        }
    }

    private function graphAccessToken(): string
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        $endpoint = (string) (config('identity.b2c.graph_token_endpoint') ?: $this->discoverTokenEndpoint() ?: "https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token");

        $clientId = (string) config('identity.b2c.graph_client_id');
        $clientSecret = (string) config('identity.b2c.graph_client_secret');
        $configuredScope = (string) config('identity.b2c.graph_scope');

        $isV1 = str_contains($endpoint, '/oauth2/token') && !str_contains($endpoint, '/oauth2/v2.0/');
        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];
        if ($isV1) {
            $resource = $configuredScope;
            if ($resource === '' || str_ends_with($resource, '/.default')) {
                $resource = 'https://graph.microsoft.com';
            } else {
                $resource = rtrim(preg_replace('#/\\.default$#', '', $resource) ?: $resource, '/');
            }
            $form['resource'] = $resource;
        } else {
            $scope = $configuredScope !== '' ? $configuredScope : 'https://graph.microsoft.com/.default';
            $form['scope'] = $scope;
        }

        $resp = Http::asForm()->post($endpoint, $form)->throw()->json();
        return (string) ($resp['access_token'] ?? '');
    }

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/graph/users/{id}",
     *   summary="Fetch Graph user by id (optional $select)",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="select", in="query", required=false, description="Comma-separated $select fields", @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="Raw Graph user JSON")
     * )
     */
    public function graphUserById(string $id, Request $request)
    {
        $token = $this->graph->accessToken();
        $base = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id);
        $select = trim((string) $request->query('select', ''));
        $url = $base;
        if ($select !== '') {
            $url .= '?%24select=' . rawurlencode($select);
        }
        $resp = Http::withToken($token)->get($url)->throw();
        return response()->json($resp->json());
    }

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/graph/users",
     *   summary="Query Graph users (supports mail eq '...')",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="mail", in="query", required=true, description="Email to filter by", @OA\Schema(type="string", format="email")),
     *   @OA\Response(response=200, description="Raw Graph users list JSON")
     * )
     */
    public function graphUsersByMail(Request $request)
    {
        $mail = trim((string) $request->query('mail', ''));
        if ($mail === '') {
            return response()->json(['message' => 'mail_required'], 400);
        }
        $token = $this->graph->accessToken();
        $escaped = str_replace("'", "''", $mail);
        $filterParam = '%24filter=' . rawurlencode("mail eq '{$escaped}'");
        $url = 'https://graph.microsoft.com/v1.0/users?' . $filterParam;
        $resp = Http::withToken($token)->get($url)->throw();
        return response()->json($resp->json());
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/b2c/graph/users/{id}",
     *   summary="Patch Graph user (pass-through)",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object")),
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function patchGraphUser(string $id, Request $request)
    {
        $token = $this->graph->accessToken();
        $body = (array) $request->json()->all();

        // Normalize common typos
        if (array_key_exists('accountEnable', $body) && !array_key_exists('accountEnabled', $body)) {
            $body['accountEnabled'] = (bool) $body['accountEnable'];
            unset($body['accountEnable']);
        }

        Http::withToken($token)
            ->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), $body)
            ->throw();

        return response()->noContent();
    }

    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/users",
     *   summary="Create Graph user (pass-through)",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(
     *       type="object",
     *       required={"accountEnabled","displayName","givenName","surname","mailNickname","mail","passwordProfile","usageLocation","extension_c1606dae4f14847a128579a35af167e_migarated","extension_c1606daee4f14847a128579a35af167e_customerId","identities"},
     *       @OA\Property(property="accountEnabled", type="boolean"),
     *       @OA\Property(property="displayName", type="string"),
     *       @OA\Property(property="givenName", type="string"),
     *       @OA\Property(property="surname", type="string"),
     *       @OA\Property(property="mailNickname", type="string"),
     *       @OA\Property(property="mail", type="string", format="email"),
     *       @OA\Property(
     *         property="passwordProfile",
     *         type="object",
     *         required={"forceChangePasswordNextSignIn","password"},
     *         @OA\Property(property="forceChangePasswordNextSignIn", type="boolean"),
     *         @OA\Property(property="password", type="string"),
     *       ),
     *       @OA\Property(property="usageLocation", type="string", minLength=2, maxLength=2),
     *       @OA\Property(property="extension_c1606dae4f14847a128579a35af167e_migarated", type="string"),
     *       @OA\Property(property="extension_c1606daee4f14847a128579a35af167e_customerId", type="integer"),
     *       @OA\Property(
     *         property="identities",
     *         type="array",
     *         minItems=1,
     *         @OA\Items(
     *           type="object",
     *           required={"signInType","issuer","issuerAssignedId"},
     *           @OA\Property(property="signInType", type="string"),
     *           @OA\Property(property="issuer", type="string"),
     *           @OA\Property(property="issuerAssignedId", type="string"),
     *         )
     *       )
     *     )
     *   ),
     *   @OA\Response(response=201, description="Created")
     * )
     */
    public function createGraphUser(Request $request)
    {
        $request->validate([
            'accountEnabled' => ['required', 'boolean'],
            'displayName' => ['required', 'string'],
            'givenName' => ['required', 'string'],
            'surname' => ['required', 'string'],
            'mailNickname' => ['required', 'string'],
            'mail' => ['required', 'string', 'email'],
            'passwordProfile' => ['required', 'array'],
            'passwordProfile.forceChangePasswordNextSignIn' => ['required', 'boolean'],
            'passwordProfile.password' => ['required', 'string'],
            'usageLocation' => ['required', 'string', 'size:2'],
            'extension_c1606dae4f14847a128579a35af167e_migarated' => ['required', 'string'],
            'extension_c1606daee4f14847a128579a35af167e_customerId' => ['required', 'integer'],
            'identities' => ['required', 'array', 'min:1'],
            'identities.*' => ['array'],
            'identities.*.signInType' => ['required', 'string'],
            'identities.*.issuer' => ['required', 'string'],
            'identities.*.issuerAssignedId' => ['required', 'string'],
        ]);

        $token = $this->graph->accessToken();
        $body = (array) $request->json()->all();
        $resp = Http::withToken($token)
            ->post('https://graph.microsoft.com/v1.0/users', $body)
            ->throw();

        return response()->json($resp->json(), 201);
    }
    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/me/items/{id}/workbook/closeSession",
     *   summary="Close Excel workbook session for drive item",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function closeWorkbookSession(string $id)
    {
        $token = $this->graph->accessToken();
        Http::withToken($token)
            ->post('https://graph.microsoft.com/v1.0/me/items/' . rawurlencode($id) . '/workbook/closeSession')
            ->throw();
        return response()->noContent();
    }

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/phoneMethods",
     *   summary="List user phone authentication methods",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="List of phone methods")
     * )
     */
    public function listPhoneMethods(string $id)
    {
        $token = $this->graph->accessToken();
        $url = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods';
        $resp = Http::withToken($token)->get($url)->throw();
        return response()->json($resp->json());
    }

    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/phoneMethods",
     *   summary="Add a phone authentication method",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"phoneNumber","phoneType"},
     *     @OA\Property(property="phoneNumber", type="string"),
     *     @OA\Property(property="phoneType", type="string", enum={"mobile","alternateMobile","office"})
     *   )),
     *   @OA\Response(response=201, description="Created")
     * )
     */
    public function addPhoneMethod(string $id, Request $request)
    {
        $token = $this->graph->accessToken();
        $body = (array) $request->json()->all();
        $url = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods';
        $resp = Http::withToken($token)->post($url, $body)->throw();
        return response()->json($resp->json(), 201);
    }

    /**
     * @OA\Delete(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/phoneMethods",
     *   summary="Delete phone authentication methods (all or by methodId)",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="methodId", in="query", required=false, description="Specific method id to delete", @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function deletePhoneMethods(string $id, Request $request)
    {
        $token = $this->graphAccessToken();
        $methodId = trim((string) $request->query('methodId', ''));
        if ($methodId !== '') {
            Http::withToken($token)
                ->delete('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods/' . rawurlencode($methodId))
                ->throw();
            return response()->noContent();
        }

        // No methodId provided: delete all phone methods
        $listUrl = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods';
        $list = Http::withToken($token)->get($listUrl)->throw()->json();
        $items = (array) ($list['value'] ?? []);
        foreach ($items as $m) {
            if (!is_array($m) || empty($m['id'])) continue;
            try {
                Http::withToken($token)
                    ->delete($listUrl . '/' . rawurlencode((string) $m['id']))
                    ->throw();
            } catch (\Throwable $e) {
                // continue deleting others
            }
        }
        return response()->noContent();
    }

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/emailMethods",
     *   summary="List user email authentication methods",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="List of email methods")
     * )
     */
    public function listEmailMethods(string $id)
    {
        $token = $this->graphAccessToken();
        $url = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/emailMethods';
        $resp = Http::withToken($token)->get($url)->throw();
        return response()->json($resp->json());
    }

    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/emailMethods",
     *   summary="Add an email authentication method",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"emailAddress"},
     *     @OA\Property(property="emailAddress", type="string", format="email")
     *   )),
     *   @OA\Response(response=201, description="Created")
     * )
     */
    public function addEmailMethod(string $id, Request $request)
    {
        $token = $this->graphAccessToken();
        $body = (array) $request->json()->all();
        $url = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/emailMethods';
        $resp = Http::withToken($token)->post($url, $body)->throw();
        return response()->json($resp->json(), 201);
    }

    /**
     * @OA\Delete(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/emailMethods",
     *   summary="Delete email authentication methods (all or by methodId)",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="methodId", in="query", required=false, description="Specific method id to delete", @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function deleteEmailMethods(string $id, Request $request)
    {
        $token = $this->graphAccessToken();
        $methodId = trim((string) $request->query('methodId', ''));
        $base = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/emailMethods';
        if ($methodId !== '') {
            Http::withToken($token)
                ->delete($base . '/' . rawurlencode($methodId))
                ->throw();
            return response()->noContent();
        }

        // Delete all email methods
        $list = Http::withToken($token)->get($base)->throw()->json();
        $items = (array) ($list['value'] ?? []);
        foreach ($items as $m) {
            if (!is_array($m) || empty($m['id'])) continue;
            try {
                Http::withToken($token)
                    ->delete($base . '/' . rawurlencode((string) $m['id']))
                    ->throw();
            } catch (\Throwable $e) {
                // continue
            }
        }
        return response()->noContent();
    }

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/methods",
     *   summary="List all authentication methods",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="List of methods")
     * )
     */
    public function listAuthMethods(string $id)
    {
        $token = $this->graphAccessToken();
        $url = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/methods';
        $resp = Http::withToken($token)->get($url)->throw();
        return response()->json($resp->json());
    }

    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/users/{id}/authentication/methods/{methodId}/resetPassword",
     *   summary="Reset password via specified auth method",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="methodId", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=false, @OA\JsonContent(type="object", @OA\Property(property="newPassword", type="string"))),
     *   @OA\Response(response=200, description="Password reset result")
     * )
     */
    public function resetPassword(string $id, string $methodId, Request $request)
    {
        $token = $this->graphAccessToken();
        $body = (array) ($request->json()->all() ?? []);
        $url = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/methods/' . rawurlencode($methodId) . '/resetPassword';
        $resp = Http::withToken($token)->post($url, $body)->throw();
        return response()->json($resp->json());
    }

    /**
     * @OA\Delete(
     *   path="/api/admin/b2c/graph/users/{id}",
     *   summary="Delete Graph user",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function deleteGraphUser(string $id)
    {
        $token = $this->graphAccessToken();
        Http::withToken($token)
            ->delete('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id))
            ->throw();
        return response()->noContent();
    }

    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/token",
     *   summary="Get Azure AD B2C Graph access token (client credentials)",
     *   tags={"Admin Directory"},
     *   @OA\Response(
     *     response=200,
     *     description="Access token payload",
     *     @OA\JsonContent(type="object",
     *       @OA\Property(property="access_token", type="string"),
     *       @OA\Property(property="token_type", type="string"),
     *       @OA\Property(property="expires_in", type="integer")
     *     )
     *   )
     * )
     */
    public function token()
    {
        $tenant = (string) (config('identity.b2c.graph_tenant') ?: config('identity.b2c.tenant'));
        $endpoint = (string) (config('identity.b2c.graph_token_endpoint') ?: $this->discoverTokenEndpoint() ?: "https://login.microsoftonline.com/{$tenant}/oauth2/v2.0/token");

        $clientId = (string) config('identity.b2c.graph_client_id');
        $clientSecret = (string) config('identity.b2c.graph_client_secret');
        $configuredScope = (string) config('identity.b2c.graph_scope');

        $isV1 = str_contains($endpoint, '/oauth2/token') && !str_contains($endpoint, '/oauth2/v2.0/');
        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ];
        if ($isV1) {
            $resource = $configuredScope;
            if ($resource === '' || str_ends_with($resource, '/.default')) {
                $resource = 'https://graph.microsoft.com';
            } else {
                $resource = rtrim(preg_replace('#/\.default$#', '', $resource) ?: $resource, '/');
            }
            $form['resource'] = $resource;
        } else {
            $scope = $configuredScope !== '' ? $configuredScope : 'https://graph.microsoft.com/.default';
            $form['scope'] = $scope;
        }

        $resp = Http::asForm()->post($endpoint, $form)->throw();

        return response()->json($resp->json());
    }
}
