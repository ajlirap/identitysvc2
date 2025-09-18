<?php

namespace App\Contracts;

interface SupportsUserAuthenticationMethods
{
    public function listPhoneMethods(string $id): array;
    public function addPhoneMethod(string $id, array $payload): array;
    public function deletePhoneMethods(string $id, ?string $methodId = null): void;

    public function listEmailMethods(string $id): array;
    public function addEmailMethod(string $id, array $payload): array;
    public function deleteEmailMethods(string $id, ?string $methodId = null): void;

    public function listAuthenticationMethods(string $id): array;
    public function resetAuthenticationMethodPassword(string $id, string $methodId, array $payload = []): array;
}
