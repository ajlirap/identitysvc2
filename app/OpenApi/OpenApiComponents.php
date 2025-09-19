<?php

namespace App\OpenApi;

/**
 * @OA\SecurityScheme(
 *   securityScheme="bearerAuth",
 *   type="http",
 *   scheme="bearer",
 *   bearerFormat="JWT",
 *   description="Enter your bearer token in the format: 'Bearer {token}' (the 'Bearer' prefix is optional in this UI)."
 * )
 */
final class OpenApiComponents {}
