<?php

namespace App\Providers\Adapters\B2C;

use App\Contracts\SupportsUserAuthenticationMethods;
use App\Contracts\SupportsUserIdentityManagement;
use App\Contracts\UserDirectoryProvider;
use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;
use App\Support\B2C\GraphClient;

class B2CUserDirectoryProvider implements UserDirectoryProvider, SupportsUserIdentityManagement, SupportsUserAuthenticationMethods
{
    public function __construct(private readonly GraphClient $graph) {}

    public function create(UserCreateRequest $req): UserProfile
    {
        $email = mb_strtolower($req->email);
        $displayName = trim(($req->firstName . ' ' . $req->lastName) ?: $email);
        $mailNickname = $this->mailNicknameFromEmail($email);

        $body = [
            'accountEnabled' => $req->isEnable,
            'displayName' => $displayName,
            'givenName' => $req->firstName,
            'surname' => $req->lastName,
            'mailNickname' => $mailNickname,
            'identities' => [[
                'signInType' => 'emailAddress',
                'issuer' => (string) config('identity.b2c.tenant'),
                'issuerAssignedId' => $email,
            ]],
            'extension_c1606daee4f14847a128579a35af167e_customerId' => $req->customerId,
            'extension_c1606dae4f14847a128579a35af167e_migrated' => false,
        ];

        $body['passwordProfile'] = [
            'password' => $req->password,
            'forceChangePasswordNextSignIn' => false,
        ];

        $res = $this->graph->post('https://graph.microsoft.com/v1.0/users', $body)->json();

        return new UserProfile(
            id: (string) $res['id'],
            email: $email,
            givenName: $req->firstName,
            familyName: $req->lastName,
            displayName: (string) ($res['displayName'] ?? $displayName),
            status: $req->isEnable ? 'active' : 'inactive',
            roles: [],
            attributes: [
                'customerId' => $req->customerId,
                'raw' => $res,
            ],
        );
    }

    public function findById(string $id): ?UserProfile
    {
        $res = $this->graph->get('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id))->json();

        if (!$res || !isset($res['id'])) {
            return null;
        }

        $email = $res['identities'][0]['issuerAssignedId'] ?? ($res['mail'] ?? '');
        $displayName = (string) ($res['displayName'] ?? $email);

        return new UserProfile(
            id: (string) $res['id'],
            email: (string) $email,
            givenName: (string) ($res['givenName'] ?? null),
            familyName: (string) ($res['surname'] ?? null),
            displayName: $displayName,
            status: ($res['accountEnabled'] ?? true) ? 'active' : 'inactive',
            roles: [],
            attributes: [
                'customerId' => $res['extension_c1606daee4f14847a128579a35af167e_customerId'] ?? null,
                'raw' => $res,
            ],
        );
    }

    public function findByEmail(string $email): ?UserProfile
    {
        // Azure AD B2C often stores local account emails in identities[].issuerAssignedId
        // and may leave user.mail empty. Use a single OR filter that matches both places
        // and then prefer a local email identity match when multiple rows are returned.
        $emailLower = mb_strtolower($email);
        $escaped = str_replace("'", "''", $emailLower); // OData escape single quotes

        $filterExpr = "(".
            "identities/any(c:c/issuerAssignedId eq '{$escaped}' and c/signInType eq 'emailAddress')".
        ") or (".
            "tolower(mail) eq '{$escaped}'".
        ") or (".
            "otherMails/any(m: tolower(m) eq '{$escaped}')".
        ") or (".
            "tolower(userPrincipalName) eq '{$escaped}'".
        ")";

        $filter = '$filter=' . rawurlencode($filterExpr);
        $select = '$select=' . rawurlencode('id,displayName,mail,accountEnabled,givenName,surname,identities,otherMails,userPrincipalName');
        $url = 'https://graph.microsoft.com/v1.0/users?' . $select . '&$top=25&' . $filter;

        $res = $this->graph->get($url)->json();
        $items = (array) ($res['value'] ?? []);
        if (empty($items)) {
            return null;
        }

        // Choose the best candidate: prefer an identities emailAddress match exactly equal to the email.
        $best = null;
        $bestHasLocalIdentity = false;
        foreach ($items as $cand) {
            if (!is_array($cand)) continue;
            $hasLocalIdentity = false;
            foreach ((array) ($cand['identities'] ?? []) as $idn) {
                if (!is_array($idn)) continue;
                $sit = strtolower((string) ($idn['signInType'] ?? ''));
                $ia = strtolower((string) ($idn['issuerAssignedId'] ?? ''));
                if ($sit === 'emailaddress' && $ia === $emailLower) {
                    $hasLocalIdentity = true;
                    break;
                }
            }
            if ($best === null || ($hasLocalIdentity && !$bestHasLocalIdentity)) {
                $best = $cand;
                $bestHasLocalIdentity = $hasLocalIdentity;
                if ($bestHasLocalIdentity) break; // perfect match found
            }
        }

        $u = $best ?: $items[0];
        $resolvedEmail = strtolower((string) ($u['mail'] ?? $emailLower));

        return new UserProfile(
            id: (string) ($u['id'] ?? ''),
            email: $resolvedEmail,
            givenName: (string) ($u['givenName'] ?? null),
            familyName: (string) ($u['surname'] ?? null),
            displayName: (string) ($u['displayName'] ?? $resolvedEmail),
            status: ($u['accountEnabled'] ?? true) ? 'active' : 'inactive',
            roles: [],
            attributes: ['raw' => $u],
        );
    }

    public function deactivate(string $id): void
    {
        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), ['accountEnabled' => false]);
    }

    public function activate(string $id): void
    {
        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), ['accountEnabled' => true]);
    }

    public function delete(string $id): void
    {
        $this->graph->delete('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id));
    }

    public function startPasswordResetPublic(string $emailOrLogin): void
    {
        // No server action: front-end should redirect to B2C password-reset policy authorize URL.
    }

    public function adminResetPassword(string $id): void
    {
        $temp = bin2hex(random_bytes(8)) . '!Aa1';
        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), [
            'passwordProfile' => [
                'password' => $temp,
                'forceChangePasswordNextSignIn' => true,
            ],
        ]);
    }

    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array
    {
        $params = ['$top' => max(1, min(100, $limit))];
        if ($cursor) {
            $params['$skiptoken'] = $cursor;
        }

        if ($query !== null && $query !== '') {
            $escaped = str_replace("'", "''", $query);
            $filterParam = '$filter=' . rawurlencode("startswith(displayName,'{$escaped}')");
            $queryString = http_build_query($params);
            $url = 'https://graph.microsoft.com/v1.0/users?' . $queryString . '&' . $filterParam;
            $resp = $this->graph->get($url);
        } else {
            $queryString = http_build_query($params);
            $url = 'https://graph.microsoft.com/v1.0/users?%24filter%20all=null' . ($queryString ? ('&' . $queryString) : '');
            $resp = $this->graph->get($url);
        }

        $data = $resp->json();
        $itemsRaw = $data['value'] ?? [];
        $items = [];
        foreach (($itemsRaw ?? []) as $u) {
            if (!is_array($u)) {
                continue;
            }
            $mail = $u['identities'][0]['issuerAssignedId'] ?? ($u['mail'] ?? '');
            $items[] = new UserProfile(
                id: (string) ($u['id'] ?? ''),
                email: (string) $mail,
                givenName: (string) ($u['givenName'] ?? null),
                familyName: (string) ($u['surname'] ?? null),
                displayName: (string) ($u['displayName'] ?? $mail),
                status: ($u['accountEnabled'] ?? true) ? 'active' : 'inactive',
                roles: [],
                attributes: [
                    'customerId' => $u['extension_c1606daee4f14847a128579a35af167e_customerId'] ?? null,
                    'raw' => $u,
                ],
            );
        }

        $nextLink = (string) ($data['@odata.nextLink'] ?? '');
        $nextCursor = null;
        if ($nextLink) {
            $parts = parse_url($nextLink);
            if (!empty($parts['query'])) {
                parse_str($parts['query'], $q);
                if (!empty($q['$skiptoken'])) {
                    $nextCursor = (string) $q['$skiptoken'];
                }
            }
        }

        return ['items' => $items, 'nextCursor' => $nextCursor];
    }

    public function updatePasswordProfile(string $id, array $passwordProfile): void
    {
        $password = (string) ($passwordProfile['password'] ?? '');
        $forceChange = isset($passwordProfile['forceChangePasswordNextSignIn'])
            ? (bool) $passwordProfile['forceChangePasswordNextSignIn']
            : true;
        if ($password === '') {
            throw new \InvalidArgumentException('Password is required');
        }

        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), [
            'passwordProfile' => [
                'password' => $password,
                'forceChangePasswordNextSignIn' => $forceChange,
            ],
        ]);
    }

    public function updateEmailIdentities(string $id, array $identities): void
    {
        $normalized = $this->normalizeIdentities($identities);
        if ($normalized === []) {
            throw new \InvalidArgumentException('At least one identity is required');
        }

        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), [
            'identities' => $normalized,
        ]);
    }

    public function updateIdentities(string $id, string $mail, array $identities, array $passwordProfile): void
    {
        $normalized = $this->normalizeIdentities($identities);
        if ($normalized === []) {
            throw new \InvalidArgumentException('At least one identity is required');
        }

        $password = (string) ($passwordProfile['password'] ?? '');
        $forceChange = isset($passwordProfile['forceChangePasswordNextSignIn'])
            ? (bool) $passwordProfile['forceChangePasswordNextSignIn']
            : true;
        if ($password === '') {
            throw new \InvalidArgumentException('Password is required');
        }

        $this->graph->patch('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id), [
            'mail' => $mail,
            'identities' => $normalized,
            'passwordProfile' => [
                'password' => $password,
                'forceChangePasswordNextSignIn' => $forceChange,
            ],
        ]);
    }

    public function listPhoneMethods(string $id): array
    {
        return $this->graph
            ->get('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods')
            ->json();
    }

    public function addPhoneMethod(string $id, array $payload): array
    {
        return $this->graph
            ->post('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods', $payload)
            ->json();
    }

    public function deletePhoneMethods(string $id, ?string $methodId = null): void
    {
        $base = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/phoneMethods';
        if ($methodId !== null && $methodId !== '') {
            $this->graph->delete($base . '/' . rawurlencode($methodId));
            return;
        }

        $list = $this->graph->get($base)->json();
        $items = (array) ($list['value'] ?? []);
        foreach ($items as $method) {
            if (!is_array($method) || empty($method['id'])) {
                continue;
            }
            try {
                $this->graph->delete($base . '/' . rawurlencode((string) $method['id']));
            } catch (\Throwable $e) {
                // ignore and continue deleting others
            }
        }
    }

    public function listEmailMethods(string $id): array
    {
        return $this->graph
            ->get('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/emailMethods')
            ->json();
    }

    public function addEmailMethod(string $id, array $payload): array
    {
        return $this->graph
            ->post('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/emailMethods', $payload)
            ->json();
    }

    public function deleteEmailMethods(string $id, ?string $methodId = null): void
    {
        $base = 'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/emailMethods';
        if ($methodId !== null && $methodId !== '') {
            $this->graph->delete($base . '/' . rawurlencode($methodId));
            return;
        }

        $list = $this->graph->get($base)->json();
        $items = (array) ($list['value'] ?? []);
        foreach ($items as $method) {
            if (!is_array($method) || empty($method['id'])) {
                continue;
            }
            try {
                $this->graph->delete($base . '/' . rawurlencode((string) $method['id']));
            } catch (\Throwable $e) {
                // ignore and continue
            }
        }
    }

    public function listAuthenticationMethods(string $id): array
    {
        return $this->graph
            ->get('https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/methods')
            ->json();
    }

    public function resetAuthenticationMethodPassword(string $id, string $methodId, array $payload = []): array
    {
        return $this->graph
            ->post(
                'https://graph.microsoft.com/v1.0/users/' . rawurlencode($id) . '/authentication/methods/' . rawurlencode($methodId) . '/resetPassword',
                $payload
            )
            ->json();
    }

    /**
     * @param array<int, array<string, mixed>> $identities
     * @return array<int, array<string, string>>
     */
    private function normalizeIdentities(array $identities): array
    {
        $normalized = [];
        foreach ($identities as $identity) {
            if (!is_array($identity)) {
                continue;
            }
            $signInType = (string) ($identity['signInType'] ?? '');
            $issuer = (string) ($identity['issuer'] ?? '');
            $issuerAssignedId = (string) ($identity['issuerAssignedId'] ?? '');
            if ($signInType === '' || $issuer === '' || $issuerAssignedId === '') {
                continue;
            }
            $normalized[] = [
                'signInType' => $signInType,
                'issuer' => $issuer,
                'issuerAssignedId' => $issuerAssignedId,
            ];
        }

        return $normalized;
    }

    private function mailNicknameFromEmail(string $email): string
    {
        $local = strstr($email, '@', true);
        $nickname = preg_replace('/[^a-z0-9]/i', '', $local ?: $email) ?: 'user';
        return substr(strtolower($nickname), 0, 64);
    }
}
