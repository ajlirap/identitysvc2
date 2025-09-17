<?php

namespace App\DTO;

class Tokens
{
    public function __construct(
        public ?string $accessToken = null,
        public ?string $refreshToken,
        public int $expiresIn,
        public ?string $idToken = null,
        public ?string $tokenType = 'Bearer',
    ) {}
}