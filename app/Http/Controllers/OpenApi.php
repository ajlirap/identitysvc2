<?php

namespace App\Http\Controllers;

/**
 * @OA\Info(
 *   title="IdentitySvc API",
 *   version="1.0.0",
 *   description="Vendor-agnostic identity facade over Azure AD B2C, Auth0, Okta, or Keycloak."
 * )
 *
 * @OA\Server(
 *   url="/",
 *   description="Application base URL"
 * )
 *
 * @OA\SecurityScheme(
 *   securityScheme="bearerAuth",
 *   type="http",
 *   scheme="bearer",
 *   bearerFormat="JWT"
 * )
 */
class OpenApi
{
}

