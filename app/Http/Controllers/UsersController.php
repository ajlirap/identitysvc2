<?php

namespace App\Http\Controllers;

use App\Contracts\SupportsUserAuthenticationMethods;
use App\Contracts\SupportsUserIdentityManagement;
use App\DTO\UserCreateRequest;
use App\Support\ProviderFactory;
use App\Support\InvitationService;
use App\Security\CaptchaVerifier;
use Illuminate\Http\Request;

class UsersController extends Controller
{
    /**
     * @OA\Get(
     *   path="/api/admin/users",
     *   summary="List users (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="q", in="query", required=false, description="Free-text search", @OA\Schema(type="string")),
     *   @OA\Parameter(name="limit", in="query", required=false, @OA\Schema(type="integer", minimum=1, maximum=200, default=50)),
     *   @OA\Parameter(name="cursor", in="query", required=false, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="List of users", @OA\JsonContent(type="object",
     *     @OA\Property(property="items", type="array", @OA\Items(ref="#/components/schemas/UserProfile")),
     *     @OA\Property(property="nextCursor", type="string", nullable=true)
     *   )),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function index(Request $request)
    {
        $q = $request->has('q') ? (string) $request->query('q') : null;
        $limit = (int) ($request->query('limit', 50));
        $cursor = $request->has('cursor') ? (string) $request->query('cursor') : null;
        $result = ProviderFactory::directory()->listUsers($q, $limit, $cursor);
        return response()->json($result);
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users",
     *   summary="Create user (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(ref="#/components/schemas/UserProfile")),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function create(Request $request)
    {
        $data = $request->validate([
            'customerId' => ['required', 'string'],
            'firstName' => ['required', 'string'],
            'lastName' => ['required', 'string'],
            'email' => ['required', 'string', 'email'],
            'isEnable' => ['sometimes', 'boolean'],
        ]);

        $dto = new UserCreateRequest(
            customerId: (string) $data['customerId'],
            firstName: (string) $data['firstName'],
            lastName: (string) $data['lastName'],
            email: mb_strtolower((string) $data['email']),
            isEnable: array_key_exists('isEnable', $data) ? (bool) $data['isEnable'] : true,
            password: bin2hex((string)$data['password']) // generate a random password; user should reset
        );

        $user = ProviderFactory::directory()->create($dto);
        return response()->json($user, 201);
    }

    /**
     * @OA\Get(
     *   path="/api/admin/users/{id}",
     *   summary="Get user (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="User", @OA\JsonContent(ref="#/components/schemas/UserProfile")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function get(string $id)
    {
        $user = ProviderFactory::directory()->findById($id);
        return $user ? response()->json($user) : response()->json(['message' => 'Not found'], 404);
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/{id}/deactivate",
     *   summary="Deactivate user (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function deactivate(string $id)
    {
        ProviderFactory::directory()->deactivate($id);
        return response()->noContent();
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/{id}/activate",
     *   summary="Activate user (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function activate(string $id)
    {
        ProviderFactory::directory()->activate($id);
        return response()->noContent();
    }

    /**
     * @OA\Post(
     *   path="/api/users/validate-email",
     *   summary="Validate email format (public)",
     *   tags={"Public"},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"email"},
     *     @OA\Property(property="email", type="string", format="email"),
     *     @OA\Property(property="captcha", type="string", nullable=true)
     *   )),
     *   @OA\Response(response=200, description="Validation result", @OA\JsonContent(type="object",
     *     @OA\Property(property="validFormat", type="boolean"),
     *     @OA\Property(property="allowedDomain", type="boolean"),
     *     @OA\Property(property="mxValid", type="boolean")
     *   )),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function validateEmail(Request $request)
    {
        $email = trim((string) $request->string('email'));

        $captcha = app(CaptchaVerifier::class);
        if ($captcha->enabled() && !$captcha->verify((string) $request->input('captcha'), $request->ip())) {
            return response()->json(['message' => 'captcha_failed'], 400);
        }
        $validFormat = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;

        $allowedDomain = true;
        $mxValid = true;

        if ($validFormat) {
            $domain = strtolower(substr(strrchr($email, '@') ?: '', 1));
            $allowedList = array_filter(array_map('trim', explode(',', (string) config('identity.email_validation.allowed_domains'))));
            $blockedList = array_filter(array_map('trim', explode(',', (string) config('identity.email_validation.blocked_domains'))));

            if (!empty($allowedList)) {
                $allowedDomain = in_array($domain, $allowedList, true);
            }
            if (!empty($blockedList) && in_array($domain, $blockedList, true)) {
                $allowedDomain = false;
            }

            $checkMx = filter_var(config('identity.email_validation.check_mx'), FILTER_VALIDATE_BOOLEAN);
            if ($checkMx) {
                try {
                    $mxValid = checkdnsrr($domain, 'MX') || checkdnsrr($domain, 'A');
                } catch (\Throwable $e) {
                    $mxValid = true;
                }
            }
        }

        return response()->json([
            'validFormat' => $validFormat,
            'allowedDomain' => $allowedDomain,
            'mxValid' => $mxValid,
        ]);
    }

    /**
     * @OA\Post(
     *   path="/api/users/password-reset/start",
     *   summary="Start password reset (public)",
     *   tags={"Public"},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"email"},
     *     @OA\Property(property="email", type="string", format="email")
     *   )),
     *   @OA\Response(response=200, description="Accepted", @OA\JsonContent(type="object",
     *     @OA\Property(property="status", type="string", example="If the account exists, an email was sent.")
     *   )),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function startPasswordReset(Request $request)
    {
        $email = (string) $request->string('email');
        ProviderFactory::directory()->startPasswordResetPublic($email);
        return response()->json(['status' => 'If the account exists, an email was sent.']);
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/{id}/password-reset",
     *   summary="Admin reset password (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function adminReset(string $id)
    {
        ProviderFactory::directory()->adminResetPassword($id);
        return response()->noContent();
    }

    /**
     * @OA\Delete(
     *   path="/api/admin/users/{id}",
     *   summary="Delete user (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function delete(string $id)
    {
        ProviderFactory::directory()->delete($id);
        return response()->noContent();
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/users/{id}/password",
     *   summary="Update a user's password profile",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"passwordProfile"},
     *     @OA\Property(property="passwordProfile", type="object",
     *       required={"password"},
     *       @OA\Property(property="password", type="string", minLength=8),
     *       @OA\Property(property="forceChangePasswordNextSignIn", type="boolean")
     *     )
     *   )),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function updatePasswordProfile(string $id, Request $request)
    {
        $data = $request->validate([
            'passwordProfile' => ['required', 'array'],
            'passwordProfile.password' => ['required', 'string', 'min:8'],
            'passwordProfile.forceChangePasswordNextSignIn' => ['sometimes', 'boolean'],
        ]);

        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserIdentityManagement) {
            return $this->notSupportedResponse('user_identity_management');
        }

        $provider->updatePasswordProfile($id, $data['passwordProfile']);
        return response()->noContent();
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/users/{id}/email-identity",
     *   summary="Replace email sign-in identities",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"identities"},
     *     @OA\Property(property="identities", type="array", minItems=1, @OA\Items(type="object",
     *       required={"signInType","issuer","issuerAssignedId"},
     *       @OA\Property(property="signInType", type="string"),
     *       @OA\Property(property="issuer", type="string"),
     *       @OA\Property(property="issuerAssignedId", type="string", format="email")
     *     ))
     *   )),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function updateEmailIdentity(string $id, Request $request)
    {
        $data = $request->validate([
            'identities' => ['required', 'array', 'min:1'],
            'identities.*' => ['array'],
            'identities.*.signInType' => ['required', 'string'],
            'identities.*.issuer' => ['required', 'string'],
            'identities.*.issuerAssignedId' => ['required', 'string', 'email'],
        ]);

        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserIdentityManagement) {
            return $this->notSupportedResponse('user_identity_management');
        }

        $provider->updateEmailIdentities($id, $data['identities']);
        return response()->noContent();
    }

    /**
     * @OA\Patch(
     *   path="/api/admin/users/{id}/identities",
     *   summary="Replace identities and password profile",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"mail","identities","passwordProfile"},
     *     @OA\Property(property="mail", type="string", format="email"),
     *     @OA\Property(property="identities", type="array", minItems=1, @OA\Items(type="object",
     *       required={"signInType","issuer","issuerAssignedId"},
     *       @OA\Property(property="signInType", type="string"),
     *       @OA\Property(property="issuer", type="string"),
     *       @OA\Property(property="issuerAssignedId", type="string", format="email")
     *     )),
     *     @OA\Property(property="passwordProfile", type="object",
     *       required={"password"},
     *       @OA\Property(property="password", type="string"),
     *       @OA\Property(property="forceChangePasswordNextSignIn", type="boolean")
     *     )
     *   )),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function updateIdentities(string $id, Request $request)
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
            'passwordProfile.forceChangePasswordNextSignIn' => ['sometimes', 'boolean'],
        ]);

        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserIdentityManagement) {
            return $this->notSupportedResponse('user_identity_management');
        }

        $provider->updateIdentities($id, $data['mail'], $data['identities'], $data['passwordProfile']);
        return response()->noContent();
    }

    /**
     * @OA\Get(
     *   path="/api/admin/users/{id}/authentication/phone-methods",
     *   summary="List phone authentication methods",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="Phone methods", @OA\JsonContent(type="array", @OA\Items(type="object"))),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function listPhoneMethods(string $id)
    {
        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        return response()->json($provider->listPhoneMethods($id));
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/{id}/authentication/phone-methods",
     *   summary="Add phone authentication method",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"phoneNumber","phoneType"},
     *     @OA\Property(property="phoneNumber", type="string"),
     *     @OA\Property(property="phoneType", type="string", enum={"mobile","alternateMobile","office"})
     *   )),
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(type="object")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function addPhoneMethod(string $id, Request $request)
    {
        $data = $request->validate([
            'phoneNumber' => ['required', 'string'],
            'phoneType' => ['required', 'string'],
        ]);

        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        $result = $provider->addPhoneMethod($id, $data);
        return response()->json($result, 201);
    }

    /**
     * @OA\Delete(
     *   path="/api/admin/users/{id}/authentication/phone-methods",
     *   summary="Delete phone authentication methods",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="methodId", in="query", required=false, description="If omitted, deletes all", @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function deletePhoneMethods(string $id, Request $request)
    {
        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        $methodId = trim((string) $request->query('methodId', ''));
        $provider->deletePhoneMethods($id, $methodId !== '' ? $methodId : null);
        return response()->noContent();
    }

    /**
     * @OA\Get(
     *   path="/api/admin/users/{id}/authentication/email-methods",
     *   summary="List email authentication methods",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="Email methods", @OA\JsonContent(type="array", @OA\Items(type="object"))),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function listEmailMethods(string $id)
    {
        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        return response()->json($provider->listEmailMethods($id));
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/{id}/authentication/email-methods",
     *   summary="Add email authentication method",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\MediaType(
     *       mediaType="application/json",
     *       @OA\Schema(
     *         type="object",
     *         required={"emailAddress"},
     *         @OA\Property(property="emailAddress", type="string", format="email", example="user@contoso.com")
     *       )
     *     )
     *   ),
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(type="object")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function addEmailMethod(string $id, Request $request)
    {
        $data = $request->validate([
            'emailAddress' => ['required', 'string', 'email'],
        ]);

        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        $result = $provider->addEmailMethod($id, $data);
        return response()->json($result, 201);
    }

    /**
     * @OA\Delete(
     *   path="/api/admin/users/{id}/authentication/email-methods",
     *   summary="Delete email authentication methods",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="methodId", in="query", required=false, description="If omitted, deletes all", @OA\Schema(type="string")),
     *   @OA\Response(response=204, description="No Content"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function deleteEmailMethods(string $id, Request $request)
    {
        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        $methodId = trim((string) $request->query('methodId', ''));
        $provider->deleteEmailMethods($id, $methodId !== '' ? $methodId : null);
        return response()->noContent();
    }

    /**
     * @OA\Get(
     *   path="/api/admin/users/{id}/authentication/methods",
     *   summary="List authentication methods",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Response(response=200, description="Authentication methods", @OA\JsonContent(type="array", @OA\Items(type="object"))),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function listAuthMethods(string $id)
    {
        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        return response()->json($provider->listAuthenticationMethods($id));
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/{id}/authentication/methods/{methodId}/reset-password",
     *   summary="Reset password via authentication method",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\Parameter(name="id", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\Parameter(name="methodId", in="path", required=true, @OA\Schema(type="string")),
     *   @OA\RequestBody(required=false, @OA\JsonContent(type="object",
     *     @OA\Property(property="newPassword", type="string", minLength=8)
     *   )),
     *   @OA\Response(response=200, description="Password reset result", @OA\JsonContent(type="object")),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=404, ref="#/components/responses/NotFound"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=501, description="Not Implemented", @OA\JsonContent(type="object",
     *     @OA\Property(property="message", type="string")
     *   ))
     * )
     */
    public function resetAuthMethodPassword(string $id, string $methodId, Request $request)
    {
        $data = $request->validate([
            'newPassword' => ['sometimes', 'string', 'min:8'],
        ]);

        $provider = ProviderFactory::directory();
        if (!$provider instanceof SupportsUserAuthenticationMethods) {
            return $this->notSupportedResponse('user_authentication_methods');
        }

        $payload = [];
        if (array_key_exists('newPassword', $data)) {
            $payload['newPassword'] = $data['newPassword'];
        }

        $result = $provider->resetAuthenticationMethodPassword($id, $methodId, $payload);
        return response()->json($result);
    }

    /**
     * @OA\Post(
     *   path="/api/users/check-active",
     *   summary="Public-safe eligibility check (non-enumerating)",
     *   tags={"Public"},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"email"},
     *     @OA\Property(property="email", type="string", format="email"),
     *     @OA\Property(property="captcha", type="string", nullable=true)
     *   )),
     *   @OA\Response(response=200, description="Generic eligibility without revealing account existence", @OA\JsonContent(type="object",
     *     @OA\Property(property="eligible", type="boolean"),
     *     @OA\Property(property="validFormat", type="boolean"),
     *     @OA\Property(property="allowedDomain", type="boolean"),
     *     @OA\Property(property="message", type="string"),
     *     @OA\Property(property="exists", type="boolean", nullable=true),
     *     @OA\Property(property="active", type="boolean", nullable=true)
     *   )),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function checkActive(Request $request)
    {
        $email = trim((string) $request->string('email'));

        $captcha = app(CaptchaVerifier::class);
        if ($captcha->enabled() && !$captcha->verify((string) $request->input('captcha'), $request->ip())) {
            return response()->json(['eligible' => false, 'validFormat' => false, 'allowedDomain' => false, 'message' => 'captcha_failed']);
        }

        try {
            usleep(random_int(120000, 240000)); // 120-240 ms
        } catch (\Throwable $e) {
            // no-op
        }

        $validFormat = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
        $allowedDomain = true;
        if ($validFormat) {
            $domain = strtolower(substr(strrchr($email, '@') ?: '', 1));
            $allowedList = array_filter(array_map('trim', explode(',', (string) config('identity.email_validation.allowed_domains'))));
            $blockedList = array_filter(array_map('trim', explode(',', (string) config('identity.email_validation.blocked_domains'))));
            if (!empty($allowedList)) {
                $allowedDomain = in_array($domain, $allowedList, true);
            }
            if (!empty($blockedList) && in_array($domain, $blockedList, true)) {
                $allowedDomain = false;
            }
        }

        $reveal = filter_var((string) config('identity.email_validation.reveal_existence'), FILTER_VALIDATE_BOOLEAN);

        $exists = null;
        $active = null;
        if ($reveal && $validFormat && $allowedDomain) {
            try {
                $user = ProviderFactory::directory()->findByEmail($email);
                $exists = $user !== null;
                $active = $exists && ($user->status === 'active');
            } catch (\Throwable $e) {
                $exists = false;
                $active = false;
            }
        }

        $eligible = $validFormat && $allowedDomain && (!$reveal || (bool) $active);
        $message = $eligible
            ? ($reveal ? 'Account exists and is active.' : 'If an account exists and is active, you can continue.')
            : 'Please use a valid email and allowed domain.';

        $payload = [
            'eligible' => $eligible,
            'validFormat' => $validFormat,
            'allowedDomain' => $allowedDomain,
            'message' => $message,
        ];
        if ($reveal) {
            $payload['exists'] = (bool) $exists;
            $payload['active'] = (bool) $active;
        }

        return response()->json($payload);
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/check-active",
     *   summary="Admin: Check if email exists and if user is active",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"email"},
     *     @OA\Property(property="email", type="string", format="email")
     *   )),
     *   @OA\Response(response=200, description="Exists/active and optional user", @OA\JsonContent(type="object",
     *     @OA\Property(property="exists", type="boolean", example=true),
     *     @OA\Property(property="active", type="boolean", example=true),
     *     @OA\Property(property="user", ref="#/components/schemas/UserProfile", nullable=true)
     *   )),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function adminCheckActive(Request $request)
    {
        $email = trim((string) $request->string('email'));
        if ($email === '' || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            return response()->json(['message' => 'invalid_email'], 400);
        }

        // Require admin role in JWT claims
        $claims = (array) $request->attributes->get('token_claims', []);
        $adminRole = (string) config('identity.common.admin_role', 'idp.admin');
        $roles = array_values(array_unique(array_merge(
            (array) ($claims['roles'] ?? []),
            (array) data_get($claims, 'realm_access.roles', [])
        )));
        if (!in_array($adminRole, $roles, true)) {
            return response()->json(['message' => 'forbidden'], 403);
        }

        $user = ProviderFactory::directory()->findByEmail($email);
        $exists = $user !== null;
        $active = $exists && ($user->status === 'active');

        return response()->json([
            'exists' => $exists,
            'active' => $active,
            'user' => $user,
        ]);
    }

    /**
     * @OA\Post(
     *   path="/api/admin/users/invite",
     *   summary="Invite user (admin)",
     *   tags={"Admin Users"},
     *   security={{"bearerAuth":{}}},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object",
     *     required={"customerId","firstName","lastName","email"},
     *     @OA\Property(property="customerId", type="string"),
     *     @OA\Property(property="firstName", type="string"),
     *     @OA\Property(property="lastName", type="string"),
     *     @OA\Property(property="email", type="string", format="email"),
     *     @OA\Property(property="isEnable", type="boolean", default=true),
     *     @OA\Property(property="password", type="string", minLength=8, nullable=true)
     *   )),
     *   @OA\Response(response=202, description="Invitation accepted", @OA\JsonContent(type="object",
     *     @OA\Property(property="status", type="string"),
     *     @OA\Property(property="details", type="object")
     *   )),
     *   @OA\Response(response=400, ref="#/components/responses/BadRequest"),
     *   @OA\Response(response=401, ref="#/components/responses/Unauthorized"),
     *   @OA\Response(response=403, ref="#/components/responses/Forbidden"),
     *   @OA\Response(response=422, ref="#/components/responses/UnprocessableEntity"),
     *   @OA\Response(response=500, ref="#/components/responses/ServerError")
     * )
     */
    public function invite(Request $request)
    {
        $data = $request->validate([
            'customerId' => ['required', 'string'],
            'firstName' => ['required', 'string'],
            'lastName' => ['required', 'string'],
            'email' => ['required', 'string', 'email'],
            'isEnable' => ['sometimes', 'boolean'],
            'password' => ['sometimes', 'string', 'min:8'],
        ]);

        $email = mb_strtolower((string) $data['email']);
        $dir = ProviderFactory::directory();
        $existing = $dir->findByEmail($email);

        $user = $existing ?: $dir->create(new UserCreateRequest(
            customerId: (string) $data['customerId'],
            firstName: (string) $data['firstName'],
            lastName: (string) $data['lastName'],
            email: $email,
            isEnable: array_key_exists('isEnable', $data) ? (bool) $data['isEnable'] : true,
            password: array_key_exists('password', $data) ? (string)$data['password'] : bin2hex(random_bytes(16)),
        ));

        $result = InvitationService::sendInvite($user);
        return response()->json(['status' => 'invited', 'details' => $result], 202);
    }

    private function notSupportedResponse(string $capability)
    {
        return response()->json([
            'message' => 'not_supported',
            'capability' => $capability,
            'vendor' => (string) config('identity.vendor'),
        ], 501);
    }
}
