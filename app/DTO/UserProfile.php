<?php

namespace App\DTO;

class UserProfile
{
    /**
     * @OA\Schema(
     *   schema="UserProfile",
     *   type="object",
     *   required={"id","email","status"},
     *   @OA\Property(property="id", type="string"),
     *   @OA\Property(property="email", type="string", format="email"),
     *   @OA\Property(property="givenName", type="string", nullable=true),
     *   @OA\Property(property="familyName", type="string", nullable=true),
     *   @OA\Property(property="displayName", type="string", nullable=true),
     *   @OA\Property(property="status", type="string", enum={"active","inactive","invited"}),
     *   @OA\Property(property="roles", type="array", @OA\Items(type="string")),
     *   @OA\Property(property="attributes", type="object")
     * )
     */
    public function __construct(
        public string $id,
        public string $email,
        public ?string $givenName = null,
        public ?string $familyName = null,
        public ?string $displayName = null,
        public string $status = 'active', // active|inactive|invited
        public array $roles = [],
        public array $attributes = [],
    ) {}
}
