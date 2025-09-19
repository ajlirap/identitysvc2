<?php

namespace App\OpenApi;

/**
 * Global OpenAPI metadata & reusable components.
 *
 * Place-only annotations file: it doesn't need any runtime code.
 */

/**
 * @OA\Info(
 *   version="1.0.0",
 *   title="Identity API",
 *   description="User directory & authentication methods"
 * )
 *
 * @OA\Server(url="/", description="Default server")
 *
 * @OA\SecurityScheme(
 *   securityScheme="bearerAuth",
 *   type="http",
 *   scheme="bearer",
 *   bearerFormat="JWT"
 * )
 */

/**
 * ====== Schemas ======
 */

/** @OA\Schema(
 *   schema="ErrorResponse",
 *   type="object",
 *   required={"message"},
 *   @OA\Property(property="message", type="string", example="invalid_email"),
 *   @OA\Property(property="details", type="object", nullable=true)
 * )
 */

/** @OA\Schema(
 *   schema="UserProfile",
 *   type="object",
 *   required={"id","customerId","firstName","lastName","email","status"},
 *   @OA\Property(property="id", type="string", example="a1b2c3"),
 *   @OA\Property(property="customerId", type="string", example="CUST-10001"),
 *   @OA\Property(property="firstName", type="string", example="Ada"),
 *   @OA\Property(property="lastName", type="string", example="Lovelace"),
 *   @OA\Property(property="email", type="string", format="email", example="ada@example.com"),
 *   @OA\Property(property="status", type="string", example="active")
 * )
 */

/** @OA\Schema(
 *   schema="PaginatedUsers",
 *   type="object",
 *   @OA\Property(property="items", type="array", @OA\Items(ref="#/components/schemas/UserProfile")),
 *   @OA\Property(property="nextCursor", type="string", nullable=true, example="eyJpZCI6IjEyMyJ9")
 * )
 */

/** @OA\Schema(
 *   schema="ValidateEmailRequest",
 *   type="object",
 *   required={"email"},
 *   @OA\Property(property="email", type="string", format="email", example="user@company.com"),
 *   @OA\Property(property="captcha", type="string", nullable=true, example="CAPTCHA_TOKEN")
 * )
 */

/** @OA\Schema(
 *   schema="ValidateEmailResult",
 *   type="object",
 *   @OA\Property(property="validFormat", type="boolean", example=true),
 *   @OA\Property(property="allowedDomain", type="boolean", example=true),
 *   @OA\Property(property="mxValid", type="boolean", example=true)
 * )
 */

/** @OA\Schema(
 *   schema="EligibilityCheck",
 *   type="object",
 *   @OA\Property(property="eligible", type="boolean", example=true),
 *   @OA\Property(property="validFormat", type="boolean", example=true),
 *   @OA\Property(property="allowedDomain", type="boolean", example=true),
 *   @OA\Property(property="message", type="string", example="If an account exists and is active, you can continue."),
 *   @OA\Property(property="exists", type="boolean", nullable=true),
 *   @OA\Property(property="active", type="boolean", nullable=true)
 * )
 */

/** @OA\Schema(
 *   schema="CreateUserRequest",
 *   type="object",
 *   required={"customerId","firstName","lastName","email"},
 *   @OA\Property(property="customerId", type="string", example="CUST-10001"),
 *   @OA\Property(property="firstName", type="string", example="Ada"),
 *   @OA\Property(property="lastName", type="string", example="Lovelace"),
 *   @OA\Property(property="email", type="string", format="email", example="ada@example.com"),
 *   @OA\Property(property="isEnable", type="boolean", default=true, example=true)
 * )
 */

/** @OA\Schema(
 *   schema="InviteUserRequest",
 *   type="object",
 *   required={"customerId","firstName","lastName","email"},
 *   @OA\Property(property="customerId", type="string"),
 *   @OA\Property(property="firstName", type="string"),
 *   @OA\Property(property="lastName", type="string"),
 *   @OA\Property(property="email", type="string", format="email"),
 *   @OA\Property(property="isEnable", type="boolean", default=true),
 *   @OA\Property(property="password", type="string", minLength=8, nullable=true)
 * )
 */

/** @OA\Schema(
 *   schema="InviteResult",
 *   type="object",
 *   @OA\Property(property="status", type="string", example="invited"),
 *   @OA\Property(property="details", type="object")
 * )
 */

/** @OA\Schema(
 *  schema="Tokens",
 *  type="object",
 *  required={"access_token","token_type","expires_in"},
 *  @OA\Property(property="access_token", type="string", example="eyJhbGciOiJSUzI1NiIsInR5cCI..."),
 *  @OA\Property(property="token_type",  type="string", example="Bearer"),
 *  @OA\Property(property="expires_in",  type="integer", example=3600),
 *  @OA\Property(property="refresh_token", type="string", nullable=true, example="0.ARwAsEi..."),
 *  @OA\Property(property="id_token", type="string", nullable=true, example="eyJraWQiOi..."),
 *  @OA\Property(property="scope", type="string", nullable=true, example="openid profile email offline_access")
 * )
 */

/** @OA\Schema(
 *  schema="RefreshRequest",
 *  type="object",
 *  required={"refresh_token"},
 *  @OA\Property(property="refresh_token", type="string", example="0.ARwAsEi...")
 * )
 */

/** @OA\Response(
 *  response="TooManyRequests",
 *  description="Too Many Requests",
 *  @OA\JsonContent(ref="#/components/schemas/ErrorResponse")
 * )
 */

/** @OA\Schema(
 *  schema="OpenIdConfiguration",
 *  type="object",
 *  @OA\Property(property="issuer", type="string"),
 *  @OA\Property(property="authorization_endpoint", type="string"),
 *  @OA\Property(property="token_endpoint", type="string"),
 *  @OA\Property(property="jwks_uri", type="string")
 * )
 */

/** @OA\Schema(
 *  schema="GraphIdentity",
 *  type="object",
 *  required={"signInType","issuer","issuerAssignedId"},
 *  @OA\Property(property="signInType", type="string", example="emailAddress"),
 *  @OA\Property(property="issuer", type="string", example="contoso.onmicrosoft.com"),
 *  @OA\Property(property="issuerAssignedId", type="string", format="email", example="john.doe@example.com")
 * )
 */

/** @OA\Schema(
 *  schema="GraphUser",
 *  type="object",
 *  @OA\Property(property="id", type="string", example="00000000-0000-0000-0000-000000000000"),
 *  @OA\Property(property="displayName", type="string", example="John Doe"),
 *  @OA\Property(property="mail", type="string", format="email", example="john.doe@example.com"),
 *  @OA\Property(property="accountEnabled", type="boolean", example=true),
 *  @OA\Property(property="identities", type="array", @OA\Items(ref="#/components/schemas/GraphIdentity"))
 * )
 */

/** @OA\Schema(
 *  schema="GraphUserMinimal",
 *  type="object",
 *  @OA\Property(property="id", type="string"),
 *  @OA\Property(property="displayName", type="string"),
 *  @OA\Property(property="mail", type="string", format="email")
 * )
 */

/** @OA\Schema(
 *  schema="GraphUsersList",
 *  type="object",
 *  @OA\Property(property="value", type="array", @OA\Items(ref="#/components/schemas/GraphUser"))
 * )
 */

/** @OA\Schema(
 *  schema="GraphAccountEnableRequest",
 *  type="object",
 *  required={"accountEnable"},
 *  @OA\Property(property="accountEnable", type="boolean", description="Set false to disable the user", example=false)
 * )
 */

/** @OA\Schema(
 *  schema="GraphPasswordProfile",
 *  type="object",
 *  required={"password","forceChangePasswordNextSignIn"},
 *  @OA\Property(property="password", type="string", minLength=8, example="Abcdef12!"),
 *  @OA\Property(property="forceChangePasswordNextSignIn", type="boolean", example=true)
 * )
 */

/** @OA\Schema(
 *  schema="GraphPasswordProfileRequest",
 *  type="object",
 *  required={"passwordProfile"},
 *  @OA\Property(property="passwordProfile", ref="#/components/schemas/GraphPasswordProfile")
 * )
 */

/** @OA\Schema(
 *  schema="GraphEmailIdentitiesRequest",
 *  type="object",
 *  required={"identities"},
 *  @OA\Property(property="identities", type="array", minItems=1, @OA\Items(ref="#/components/schemas/GraphIdentity"))
 * )
 */

/** @OA\Schema(
 *  schema="GraphIdentitiesAndPasswordRequest",
 *  type="object",
 *  required={"mail","identities","passwordProfile"},
 *  @OA\Property(property="mail", type="string", format="email", example="john.doe@example.com"),
 *  @OA\Property(property="identities", type="array", minItems=1, @OA\Items(ref="#/components/schemas/GraphIdentity")),
 *  @OA\Property(property="passwordProfile", ref="#/components/schemas/GraphPasswordProfile")
 * )
 */

/** @OA\Schema(
 *  schema="GraphPhoneMethod",
 *  type="object",
 *  @OA\Property(property="id", type="string", example="3d8e873c"),
 *  @OA\Property(property="phoneNumber", type="string", example="+1 5555550100"),
 *  @OA\Property(property="phoneType", type="string", example="mobile")
 * )
 */

/** @OA\Schema(
 *  schema="GraphPhoneMethodCreateRequest",
 *  type="object",
 *  required={"phoneNumber","phoneType"},
 *  @OA\Property(property="phoneNumber", type="string", example="+1 5555550100"),
 *  @OA\Property(property="phoneType", type="string", enum={"mobile","alternateMobile","office"})
 * )
 */

/** @OA\Schema(
 *  schema="GraphPhoneMethodsList",
 *  type="object",
 *  @OA\Property(property="value", type="array", @OA\Items(ref="#/components/schemas/GraphPhoneMethod"))
 * )
 */

/** @OA\Schema(
 *  schema="GraphEmailMethod",
 *  type="object",
 *  @OA\Property(property="id", type="string", example="emailMethodId"),
 *  @OA\Property(property="emailAddress", type="string", format="email", example="john.doe@example.com"),
 *  @OA\Property(property="isPrimary", type="boolean", example=true)
 * )
 */

/** @OA\Schema(
 *  schema="GraphEmailMethodCreateRequest",
 *  type="object",
 *  required={"emailAddress"},
 *  @OA\Property(property="emailAddress", type="string", format="email", example="john.doe@example.com")
 * )
 */

/** @OA\Schema(
 *  schema="GraphEmailMethodsList",
 *  type="object",
 *  @OA\Property(property="value", type="array", @OA\Items(ref="#/components/schemas/GraphEmailMethod"))
 * )
 */

/** @OA\Schema(
 *  schema="GraphAuthMethod",
 *  type="object",
 *  @OA\Property(property="id", type="string"),
 *  @OA\Property(property="displayName", type="string"),
 *  @OA\Property(property="@odata.type", type="string", example="#microsoft.graph.microsoftAuthenticatorAuthenticationMethod")
 * )
 */

/** @OA\Schema(
 *  schema="GraphAuthMethodsList",
 *  type="object",
 *  @OA\Property(property="value", type="array", @OA\Items(ref="#/components/schemas/GraphAuthMethod"))
 * )
 */

/** @OA\Schema(
 *  schema="GraphResetPasswordRequest",
 *  type="object",
 *  @OA\Property(property="newPassword", type="string", minLength=8, example="Abcdef12!")
 * )
 */

/** @OA\Schema(
 *  schema="GraphResetPasswordResult",
 *  type="object",
 *  @OA\Property(property="status", type="string", example="success"),
 *  @OA\Property(property="temporaryPassword", type="string", example="Abcdef12!", nullable=true)
 * )
 */

/**
 * ====== Common Responses ======
 */

/** @OA\Response(
 *   response="BadRequest",
 *   description="Bad Request",
 *   @OA\JsonContent(ref="#/components/schemas/ErrorResponse")
 * )
 */

/** @OA\Response(
 *   response="Unauthorized",
 *   description="Unauthorized",
 *   @OA\JsonContent(ref="#/components/schemas/ErrorResponse")
 * )
 */

/** @OA\Response(
 *   response="Forbidden",
 *   description="Forbidden",
 *   @OA\JsonContent(ref="#/components/schemas/ErrorResponse")
 * )
 */

/** @OA\Response(
 *   response="NotFound",
 *   description="Not Found",
 *   @OA\JsonContent(ref="#/components/schemas/ErrorResponse")
 * )
 */

/** @OA\Response(
 *   response="UnprocessableEntity",
 *   description="Validation failed",
 *   @OA\JsonContent(
 *     type="object",
 *     @OA\Property(property="message", type="string", example="The given data was invalid."),
 *     @OA\Property(
 *       property="errors",
 *       type="object",
 *       additionalProperties=@OA\Schema(type="array", @OA\Items(type="string")),
 *       example={"email":{"The email field must be a valid email address."}}
 *     )
 *   )
 * )
 */

/** @OA\Response(
 *   response="ServerError",
 *   description="Server Error",
 *   @OA\JsonContent(ref="#/components/schemas/ErrorResponse")
 * )
 */
final class OpenApiComponents
{
    // Intentionally empty: annotations-only holder
}
