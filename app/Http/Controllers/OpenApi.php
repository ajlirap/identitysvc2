<?php

namespace App\Http\Controllers;

/**
 * @OA\Info(
 *   title="IdentitySvc API",
 *   version="1.0.0",
 *   description="Vendor-agnostic identity facade over Azure AD B2C, Auth0, Okta, or Keycloak."
 * )
 *
 * @OA\Response(
 *   response="BadRequest",
 *   description="Bad Request",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="details", type="object", nullable=true)
 *   )
 * )
 *
 * @OA\Response(
 *   response="Unauthorized",
 *   description="Unauthorized",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="details", type="object", nullable=true)
 *   )
 * )
 *
 * @OA\Response(
 *   response="Forbidden",
 *   description="Forbidden",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="details", type="object", nullable=true)
 *   )
 * )
 *
 * @OA\Response(
 *   response="NotFound",
 *   description="Not Found",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="details", type="object", nullable=true)
 *   )
 * )
 *
 * @OA\Response(
 *   response="UnprocessableEntity",
 *   description="Validation failed",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="errors", type="object")
 *   )
 * )
 *
 * @OA\Response(
 *   response="TooManyRequests",
 *   description="Too Many Requests",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="details", type="object", nullable=true)
 *   )
 * )
 *
 * @OA\Response(
 *   response="ServerError",
 *   description="Server Error",
 *   @OA\JsonContent(type="object",
 *     @OA\Property(property="message", type="string"),
 *     @OA\Property(property="details", type="object", nullable=true)
 *   )
 * )
 */
class OpenApi
{
}
