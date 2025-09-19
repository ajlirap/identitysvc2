<?php

namespace App\DTO;

/**
 * @OA\Schema(
 *   schema="Tokens",
 *   type="object",
 *   required={"expiresIn"},
 *   @OA\Property(property="accessToken", type="string", nullable=true, description="Access token issued by the identity provider"),
 *   @OA\Property(property="refreshToken", type="string", nullable=true, description="Refresh token that can be used to obtain new access tokens"),
 *   @OA\Property(property="expiresIn", type="integer", description="Lifetime of the access token in seconds", example=3600),
 *   @OA\Property(property="idToken", type="string", nullable=true, description="ID token (when available)"),
 *   @OA\Property(property="tokenType", type="string", nullable=true, description="Token type as reported by the provider", example="Bearer")
 * )
 */
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

