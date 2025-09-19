<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Http;
use Illuminate\Http\Request;
use App\Support\B2C\GraphClient;

class B2CGraphController extends Controller
{
    public function __construct(private readonly GraphClient $graph) {}

    /**
     * @OA\Get(
     *   path="/api/admin/b2c/openid-configuration",
     *   summary="Get OpenID configuration for the tenant",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Response(response=200, description="OIDC discovery document", @OA\JsonContent(ref="#/components/schemas/OpenIdConfiguration")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Parameter(name="select", in="query", required=false, description="Comma-separated $select fields", @OA\Schema(type="string"), example="id,displayName,mail,identities"),
     *   @OA\Response(response=200, description="Raw Graph user JSON", @OA\JsonContent(ref="#/components/schemas/GraphUser")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   summary="Query Graph users by email",
     *   description="Pass-through to Microsoft Graph with a filter 'mail eq {email}'.",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="mail", in="query", required=true, description="Email to filter by", @OA\Schema(type="string", format="email")),
     *   @OA\Response(response=200, description="Users list", @OA\JsonContent(ref="#/components/schemas/GraphUsersList")),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   summary="Enable/Disable user account",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(ref="#/components/schemas/GraphAccountEnableRequest")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function patchGraphUser(string $id, Request $request)
    {
        $request->validate([
            'accountEnable' => ['required', 'boolean'],
        ]);

        $token = $this->graph->accessToken();
        $body = [
            'accountEnabled' => $request->boolean('accountEnable'),
        ];

        Http::withToken($token)
            ->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), $body)
            ->throw();

        return response()->noContent();
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/b2c/graph/users/{id}/password",
     *   summary="Update a user's password profile",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA	JsonContent(ref="#/components/schemas/GraphPasswordProfileRequest")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA	Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA	Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA	Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA	Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function patchGraphUserPassword(string $id, Request $request)
    {
        $data = $request->validate([
            'passwordProfile' => ['required', 'array'],
            'passwordProfile.password' => ['required', 'string', 'min:8'],
            'passwordProfile.forceChangePasswordNextSignIn' => ['required', 'boolean'],
        ]);

        $body = [
            'passwordProfile' => [
                'password' => $data['passwordProfile']['password'],
                'forceChangePasswordNextSignIn' => (bool) $data['passwordProfile']['forceChangePasswordNextSignIn'],
            ],
        ];

        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), $body);

        return response()->noContent();
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/b2c/graph/users/{id}/email-identity",
     *   summary="Update a user's email sign-in identity",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(ref="#/components/schemas/GraphEmailIdentitiesRequest")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA	Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA	Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA	Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA	Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function patchGraphUserEmailIdentity(string $id, Request $request)
    {
        $data = $request->validate([
            'identities' => ['required', 'array', 'min:1'],
            'identities.*' => ['array'],
            'identities.*.signInType' => ['required', 'string'],
            'identities.*.issuer' => ['required', 'string'],
            'identities.*.issuerAssignedId' => ['required', 'string', 'email'],
        ]);

        $body = [
            'identities' => array_map(
                static fn(array $identity) => [
                    'signInType' => (string) $identity['signInType'],
                    'issuer' => (string) $identity['issuer'],
                    'issuerAssignedId' => (string) $identity['issuerAssignedId'],
                ],
                $data['identities']
            ),
        ];

        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), $body);

        return response()->noContent();
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/b2c/graph/users/{id}/identities",
     *   summary="Update identities and password profile for a user",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(ref="#/components/schemas/GraphIdentitiesAndPasswordRequest")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA	Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA	Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA	Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA	Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function patchGraphUserIdentities(string $id, Request $request)
    {
        $data = $request->validate([
            'mail' => ['required', 'string', 'email'],
            'identities' => ['required', 'array', 'min:1'],
            'identities.*' => ['array'],
            'identities.*.signInType' => ['required', 'string'],
            'identities.*.issuer' => ['required', 'string'],
            'identities.*.issuerAssignedId' => ['required', 'string', 'email'],
            'passwordProfile' => ['required', 'array'],
            'passwordProfile.password' => ['required', 'string', 'min:8'],
            'passwordProfile.forceChangePasswordNextSignIn' => ['required', 'boolean'],
        ]);

        $body = [
            'mail' => $data['mail'],
            'identities' => array_map(
                static fn(array $identity) => [
                    'signInType' => (string) $identity['signInType'],
                    'issuer' => (string) $identity['issuer'],
                    'issuerAssignedId' => (string) $identity['issuerAssignedId'],
                ],
                $data['identities']
            ),
            'passwordProfile' => [
                'password' => $data['passwordProfile']['password'],
                'forceChangePasswordNextSignIn' => (bool) $data['passwordProfile']['forceChangePasswordNextSignIn'],
            ],
        ];

        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), $body);

        return response()->noContent();
    }

    /**
     * @OA\Post(
     *   path="/api/admin/b2c/graph/users",
     *   summary="Create Graph user (pass-through)",
     *   tags={"Admin Directory"},
     *   security={{"bearerAuth":{}}},
     *   @OA\RequestBody(required=true, @OA\JsonContent(ref="#/components/schemas/GraphCreateUserRequest")),
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(ref="#/components/schemas/GraphUserMinimal")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=200, description="List of phone methods", @OA\JsonContent(ref="#/components/schemas/GraphPhoneMethodsList")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\RequestBody(required=true, @OA\JsonContent(ref="#/components/schemas/GraphPhoneMethodCreateRequest")),
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(ref="#/components/schemas/GraphPhoneMethod")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=200, description="List of email methods", @OA\JsonContent(ref="#/components/schemas/GraphEmailMethodsList")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\RequestBody(required=true, @OA\JsonContent(ref="#/components/schemas/GraphEmailMethodCreateRequest")),
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(ref="#/components/schemas/GraphEmailMethod")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=200, description="List of methods", @OA\JsonContent(ref="#/components/schemas/GraphAuthMethodsList")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA	Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA	Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\RequestBody(required=false, @OA\JsonContent(ref="#/components/schemas/GraphResetPasswordRequest")),
     *   @OA\Response(response=200, description="Password reset result", @OA\JsonContent(ref="#/components/schemas/GraphResetPasswordResult")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA	Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA	Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA	Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA	Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA	Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA	Response(response=500, ref="#/components/responses/ServerError")
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
     *   @OA\Response(response=200, description="Access token payload", @OA\JsonContent(ref="#/components/schemas/Tokens")),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
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
