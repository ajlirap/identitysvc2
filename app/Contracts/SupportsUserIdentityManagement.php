<?php

namespace App\Contracts;

interface SupportsUserIdentityManagement
{
    /**
     * Update a user's password profile (e.g., Graph passwordProfile payload).
     */
    public function updatePasswordProfile(string $id, array $passwordProfile): void;

    /**
     * Replace the set of email identities attached to the user.
     */
    public function updateEmailIdentities(string $id, array $identities): void;

    /**
     * Replace identities, mail attribute, and password profile in one operation.
     */
    public function updateIdentities(string $id, string $mail, array $identities, array $passwordProfile): void;
}
