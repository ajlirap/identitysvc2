<?php

namespace App\DTO;

class UserCreateRequest
{
    public function __construct(
        public string $customerId,
        public string $firstName,
        public string $lastName,
        public string $email,
        public bool $isEnable = true,
        public string $password,
    ) {}
}
