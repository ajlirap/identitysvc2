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
        $email = mb_strtolower($email);

        // Query by issuerAssignedId only (broad), then select the best match locally.
        // Issuer strings vary across tenants; filtering on issuer can cause false negatives.
        $filter = rawurlencode("identities/any(c:c/issuerAssignedId eq '{$email}')");
        $select = '$select=' . rawurlencode('id,displayName,identities,accountEnabled,givenName,surname,mail');
        $url = 'https://graph.microsoft.com/v1.0/users?'.$select.'&$top=25&$filter=' . $filter;
        $res = $this->graph->get($url)->json();
        $items = (array) ($res['value'] ?? []);
        if (empty($items)) {
            return null;
        }

        $preferredIssuers = $this->candidateIssuers();

        $best = null;
        $bestScore = -1;
        foreach ($items as $cand) {
            if (!is_array($cand)) continue;
            $score = $this->emailIdentityMatchScore($cand, $email, $preferredIssuers);
            if ($score > $bestScore) {
                $best = $cand;
                $bestScore = $score;
            }
        }

        if (!$best) {
            return null;
        }

        $resolvedEmail = $this->extractEmailFromUser($best) ?: $email;

        return new UserProfile(
            id: (string) ($best['id'] ?? ''),
            email: $resolvedEmail,
            givenName: (string) ($best['givenName'] ?? null),
            familyName: (string) ($best['surname'] ?? null),
            displayName: (string) ($best['displayName'] ?? $resolvedEmail),
            status: ($best['accountEnabled'] ?? true) ? 'active' : 'inactive',
            roles: [],
            attributes: [
                'raw' => $best,
            ],
        );
    }

    private function candidateIssuers(): array
    {
        $tenant = (string) config('identity.b2c.tenant');
        $tenantId = (string) config('identity.b2c.tenant_id');
        $domain = strtolower((string) preg_replace('/^https?:\/\//i', '', (string) config('identity.b2c.domain')));

        $candidates = [];
        if ($tenant !== '') $candidates[] = strtolower($tenant);
        if ($tenantId !== '') $candidates[] = strtolower($tenantId);
        if ($domain !== '') $candidates[] = $domain;

        // Also include <tenant>.onmicrosoft.com variant if not present
        if ($tenant !== '') {
            $onmicrosoft = preg_match('/\.onmicrosoft\.com$/i', $tenant) ? $tenant : ($tenant . '.onmicrosoft.com');
            $candidates[] = strtolower($onmicrosoft);
        }

        return array_values(array_unique(array_filter($candidates)));
    }

    private function emailIdentityMatchScore(array $user, string $email, array $preferredIssuers): int
    {
        $identities = (array) ($user['identities'] ?? []);
        $score = -1;
        foreach ($identities as $idn) {
            if (!is_array($idn)) continue;
            $signInType = strtolower((string) ($idn['signInType'] ?? ''));
            $issuerAssignedId = strtolower((string) ($idn['issuerAssignedId'] ?? ''));
            $issuer = strtolower((string) ($idn['issuer'] ?? ''));
            if ($issuerAssignedId !== $email) continue;

            // Base match
            $s = 1;
            // Prefer local emailAddress identities
            if ($signInType === 'emailaddress') $s += 2;
            // Prefer issuer matching configured candidates
            if (in_array($issuer, $preferredIssuers, true)) $s += 3;

            $score = max($score, $s);
        }
        return $score;
    }

    private function extractEmailFromUser(array $user): ?string
    {
        $identities = (array) ($user['identities'] ?? []);
        foreach ($identities as $idn) {
            if (!is_array($idn)) continue;
            $signInType = strtolower((string) ($idn['signInType'] ?? ''));
            if ($signInType === 'emailaddress' && !empty($idn['issuerAssignedId'])) {
                return strtolower((string) $idn['issuerAssignedId']);
            }
        }
        if (!empty($user['mail'])) return strtolower((string) $user['mail']);
        return null;
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
