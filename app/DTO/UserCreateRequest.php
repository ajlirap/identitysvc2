<?php

namespace App\DTO;

class UserCreateRequest
{
    public function __construct(
        public string $email,
        public ?string $givenName = null,
        public ?string $familyName = null,
        public array $roles = [],
        public array $attributes = [],
        public bool $invite = true,
    ) {}
}

