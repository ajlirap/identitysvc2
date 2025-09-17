<?php

namespace App\Http\Controllers;

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
     *   @OA\Parameter(name="q", in="query", required=false, @OA\Schema(type="string")),
     *   @OA\Parameter(name="limit", in="query", required=false, @OA\Schema(type="integer", minimum=1, maximum=200, default=50)),
     *   @OA\Parameter(name="cursor", in="query", required=false, @OA\Schema(type="string")),
     *   @OA\Response(
     *     response=200,
     *     description="List of users",
     *     @OA\JsonContent(
     *       type="object",
     *       @OA\Property(property="items", type="array", @OA\Items(ref="#/components/schemas/UserProfile")),
     *       @OA\Property(property="nextCursor", type="string", nullable=true)
     *     )
     *   )
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
     *   @OA\RequestBody(
     *     required=true,
     *     @OA\JsonContent(type="object",
     *       required={"email"},
     *       @OA\Property(property="email", type="string", format="email"),
     *       @OA\Property(property="givenName", type="string"),
     *       @OA\Property(property="familyName", type="string"),
     *       @OA\Property(property="roles", type="array", @OA\Items(type="string")),
     *       @OA\Property(property="attributes", type="object"),
     *       @OA\Property(property="invite", type="boolean", default=true)
     *     )
     *   ),
     *   @OA\Response(response=201, description="Created", @OA\JsonContent(ref="#/components/schemas/UserProfile"))
     * )
     */
    public function create(Request $request)
    {
        $dto = new UserCreateRequest(
            email: (string) $request->string('email'),
            givenName: $request->string('givenName'),
            familyName: $request->string('familyName'),
            roles: (array) $request->input('roles', []),
            attributes: (array) $request->input('attributes', []),
            invite: (bool) $request->boolean('invite', true),
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
     *   @OA\Response(response=404, description="Not Found")
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
     *   @OA\Response(response=204, description="No Content")
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
     *   @OA\Response(response=204, description="No Content")
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
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object", required={"email"}, @OA\Property(property="email", type="string", format="email"))),
     *   @OA\Response(response=200, description="Validation result", @OA\JsonContent(type="object",
     *     @OA\Property(property="validFormat", type="boolean"),
     *     @OA\Property(property="allowedDomain", type="boolean"),
     *     @OA\Property(property="mxValid", type="boolean")
     *   ))
     * )
     */
    public function validateEmail(Request $request)
    {
        $email = trim((string) $request->string('email'));

        // Optional CAPTCHA guard
        $captcha = app(CaptchaVerifier::class);
        if ($captcha->enabled() && !$captcha->verify((string) $request->input('captcha'), $request->ip())) {
            return response()->json(['message' => 'captcha_failed'], 400);
        }
        $validFormat = filter_var($email, FILTER_VALIDATE_EMAIL) !== false;

        // Default allowed; only constrain if configured
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
                // MX check only if domain looks sane; if DNS check fails or is slow, treat as not strictly invalid
                try {
                    $mxValid = checkdnsrr($domain, 'MX') || checkdnsrr($domain, 'A');
                } catch (\Throwable $e) {
                    $mxValid = true; // do not block due to DNS errors; keeps behavior non-enumerating and resilient
                }
            }
        }

        // Non-enumerating: do not reveal whether the email exists in the directory
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
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object", required={"email"}, @OA\Property(property="email", type="string", format="email"))),
     *   @OA\Response(response=200, description="Accepted")
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
     *   @OA\Response(response=204, description="No Content")
     * )
     */
    public function adminReset(string $id)
    {
        ProviderFactory::directory()->adminResetPassword($id);
        return response()->noContent();
    }

    /**
     * @OA\Post(
     *   path="/api/users/check-active",
     *   summary="Public-safe eligibility check (non-enumerating)",
     *   tags={"Public"},
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object", required={"email"},
     *     @OA\Property(property="email", type="string", format="email")
     *   )),
     *   @OA\Response(
     *     response=200,
     *     description="Generic eligibility without revealing account existence",
     *     @OA\JsonContent(type="object",
     *       @OA\Property(property="eligible", type="boolean"),
     *       @OA\Property(property="validFormat", type="boolean"),
     *       @OA\Property(property="allowedDomain", type="boolean"),
     *       @OA\Property(property="message", type="string")
     *     )
     *   )
     * )
     */
    public function checkActive(Request $request)
    {
        $email = trim((string) $request->string('email'));

        // Optional CAPTCHA guard
        $captcha = app(CaptchaVerifier::class);
        if ($captcha->enabled() && !$captcha->verify((string) $request->input('captcha'), $request->ip())) {
            return response()->json(['eligible' => false, 'validFormat' => false, 'allowedDomain' => false, 'message' => 'captcha_failed']);
        }

        // Add small jitter to reduce timing-based enumeration
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

        // Determine behavior based on config: by default, do NOT reveal existence
        $reveal = filter_var((string) config('identity.email_validation.reveal_existence'), FILTER_VALIDATE_BOOLEAN);

        $exists = null;
        $active = null;
        if ($reveal && $validFormat && $allowedDomain) {
            try {
                $user = ProviderFactory::directory()->findByEmail($email);
                $exists = $user !== null;
                $active = $exists && ($user->status === 'active');
            } catch (\Throwable $e) {
                // On provider errors, do not leak specifics; treat as non-existent
                $exists = false;
                $active = false;
            }
        }

        // Eligible means "may proceed"; if revealing, require active account
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
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object", required={"email"},
     *     @OA\Property(property="email", type="string", format="email")
     *   )),
     *   @OA\Response(
     *     response=200,
     *     description="Exists/active and optional user",
     *     @OA\JsonContent(type="object",
     *       @OA\Property(property="exists", type="boolean"),
     *       @OA\Property(property="active", type="boolean"),
     *       @OA\Property(property="user", ref="#/components/schemas/UserProfile", nullable=true)
     *     )
     *   ),
     *   @OA\Response(response=400, description="Bad Request"),
     *   @OA\Response(response=403, description="Forbidden"),
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
     *   @OA\RequestBody(required=true, @OA\JsonContent(type="object", required={"email"},
     *     @OA\Property(property="email", type="string", format="email"),
     *     @OA\Property(property="givenName", type="string"),
     *     @OA\Property(property="familyName", type="string")
     *   )),
     *   @OA\Response(response=202, description="Invitation accepted")
     * )
     */
    public function invite(Request $request)
    {
        $email = (string) $request->string('email');
        $given = $request->string('givenName');
        $family = $request->string('familyName');

        $dir = ProviderFactory::directory();
        $existing = $dir->findByEmail($email);
        $user = $existing ?: $dir->create(new UserCreateRequest(
            email: $email,
            givenName: $given,
            familyName: $family,
            invite: true,
        ));

        $result = InvitationService::sendInvite($user);
        return response()->json(['status' => 'invited', 'details' => $result], 202);
    }
}
