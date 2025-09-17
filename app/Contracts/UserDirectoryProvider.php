<?php

namespace App\Contracts;

use App\DTO\UserCreateRequest;
use App\DTO\UserProfile;

interface UserDirectoryProvider
{
    public function create(UserCreateRequest $req): UserProfile; // invite or temp password
    public function findById(string $id): ?UserProfile;
    public function findByEmail(string $email): ?UserProfile; // admin-only usage
    public function deactivate(string $id): void;
    public function activate(string $id): void;
    public function startPasswordResetPublic(string $emailOrLogin): void; // hosted reset link flow
    public function adminResetPassword(string $id): void; // force change on next login
    /**
     * List users with optional search and pagination.
     * Returns ['items' => UserProfile[], 'nextCursor' => ?string]
     */
    public function listUsers(?string $query = null, int $limit = 50, ?string $cursor = null): array;
}
