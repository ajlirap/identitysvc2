<?php

/*
|--------------------------------------------------------------------------
| Identity Service Configuration
|--------------------------------------------------------------------------
|
| Keycloak quick test checklist:
| - Enable service account on your confidential client.
| - Assign realm-management roles: view-users, query-users, manage-users (optional: query-groups).
| - Set env: IDENTITY_VENDOR=keycloak, KC_BASE_URL, KC_REALM, KC_CLIENT_ID, KC_CLIENT_SECRET, KC_ISSUER, KC_JWKS_URI.
| - Verify by obtaining a client-credentials token and calling the Admin API users endpoint.
|
*/

return [
    'vendor' => env('IDENTITY_VENDOR', 'b2c'), // b2c|auth0|okta|keycloak

    'common' => [
        'audience' => env('ID_AUDIENCE', 'api://identitysvc'),
        'cache_ttl' => env('ID_JWKS_TTL', 3600),
        'leeway' => env('ID_JWT_LEEWAY', 60),
        'admin_role' => env('ID_ADMIN_ROLE', 'idp.admin'),
    ],

    // Public email pre-check controls (non-enumerating)
    'email_validation' => [
        // Comma-separated allow/deny lists (domains only), optional
        'allowed_domains' => env('EMAIL_ALLOWED_DOMAINS', ''),
        'blocked_domains' => env('EMAIL_BLOCKED_DOMAINS', ''),
        // Optional MX DNS check (can be slow on some hosts); default off
        'check_mx' => env('EMAIL_VALIDATE_MX', false),
        // Optional: reveal existence/active on public check-active (risk: user enumeration)
        'reveal_existence' => env('EMAIL_REVEAL_EXISTENCE', false),
    ],

    'b2c' => [
        'tenant' => env('B2C_TENANT'),
        'domain' => env('B2C_DOMAIN'),
        'tenant_id' => env('B2C_TENANT_ID'),
        'policy_signin' => env('B2C_POLICY_SIGNIN'),
        'policy_password_reset' => env('B2C_POLICY_PASSWORD_RESET'),
        'client_id' => env('B2C_CLIENT_ID'),
        'client_secret' => env('B2C_CLIENT_SECRET'),
        'redirect_uri' => env('B2C_REDIRECT_URI'),
        'scope' => env('B2C_SCOPE', 'openid offline_access'),
        // For confidential clients with B2C, PKCE is optional.
        // Set to true to include PKCE in the authorize URL and token exchange.
        'use_pkce' => env('B2C_USE_PKCE', false),
        // Leave the following blank to auto-discover per policy; set only to override defaults.
        'discovery_endpoint' => env('B2C_DISCOVERY_ENDPOINT'),
        'token_endpoint' => env('B2C_TOKEN_ENDPOINT'),
        'authorize_endpoint' => env('B2C_AUTHORIZE_ENDPOINT'),
        'issuer' => env('B2C_ISSUER'),
        'jwks_uri' => env('B2C_JWKS_URI'),
        // Admin (Graph) - for lifecycle
        'enable_raw_routes' => env('B2C_GRAPH_RAW_ROUTES', true),
        'graph_tenant' => env('B2C_GRAPH_TENANT'),
        'graph_token_endpoint' => env('B2C_GRAPH_TOKEN_ENDPOINT'),
        'graph_client_id' => env('B2C_GRAPH_CLIENT_ID'),
        'graph_client_secret' => env('B2C_GRAPH_CLIENT_SECRET'),
        'graph_scope' => env('B2C_GRAPH_SCOPE', 'https://graph.microsoft.com/.default'),
    ],

    'auth0' => [
        'domain' => env('AUTH0_DOMAIN'),
        'client_id' => env('AUTH0_CLIENT_ID'),
        'client_secret' => env('AUTH0_CLIENT_SECRET'),
        'redirect_uri' => env('AUTH0_REDIRECT_URI'),
        'audience' => env('AUTH0_AUDIENCE'),
        'jwks_uri' => env('AUTH0_JWKS_URI'),
        'issuer' => env('AUTH0_ISSUER'),
        // Management API
        'mgmt_client_id' => env('AUTH0_MGMT_CLIENT_ID'),
        'mgmt_client_secret' => env('AUTH0_MGMT_CLIENT_SECRET'),
        'mgmt_audience' => env('AUTH0_MGMT_AUDIENCE'),
    ],

    'okta' => [
        'domain' => env('OKTA_DOMAIN'),
        'client_id' => env('OKTA_CLIENT_ID'),
        'client_secret' => env('OKTA_CLIENT_SECRET'),
        'redirect_uri' => env('OKTA_REDIRECT_URI'),
        'issuer' => env('OKTA_ISSUER'),
        'jwks_uri' => env('OKTA_JWKS_URI'),
        // Admin
        'api_token' => env('OKTA_API_TOKEN'),
    ],

    'keycloak' => [
        'realm' => env('KC_REALM'),
        'base_url' => env('KC_BASE_URL'),
        'client_id' => env('KC_CLIENT_ID'),
        'client_secret' => env('KC_CLIENT_SECRET'),
        'redirect_uri' => env('KC_REDIRECT_URI'),
        'issuer' => env('KC_ISSUER'),
        'jwks_uri' => env('KC_JWKS_URI'),
        // Admin
        'admin_user' => env('KC_ADMIN_USER'),
        'admin_pass' => env('KC_ADMIN_PASS'),
    ],

    // Optional CAPTCHA verification for public endpoints
    'captcha' => [
        'enabled' => env('CAPTCHA_ENABLED', false),
        // 'recaptcha' | 'turnstile'
        'provider' => env('CAPTCHA_PROVIDER', 'recaptcha'),
        'secret' => env('CAPTCHA_SECRET'),
        // Minimum score for reCAPTCHA v3 (0.0 - 1.0)
        'min_score' => env('CAPTCHA_MIN_SCORE', 0.5),
        // Verification endpoints (override if needed)
        'verify_url' => [
            'recaptcha' => env('CAPTCHA_RECAPTCHA_VERIFY_URL', 'https://www.google.com/recaptcha/api/siteverify'),
            'turnstile' => env('CAPTCHA_TURNSTILE_VERIFY_URL', 'https://challenges.cloudflare.com/turnstile/v0/siteverify'),
        ],
    ],

    // Tracing / Correlation IDs
    'tracing' => [
        'correlation_id_header' => env('TRACE_CORRELATION_HEADER', 'X-Correlation-Id'),
        'request_id_header'     => env('TRACE_REQUEST_HEADER', 'X-Request-Id'),
        'traceparent_header'    => env('TRACE_TRACEPARENT_HEADER', 'traceparent'),
        'tracestate_header'     => env('TRACE_TRACESTATE_HEADER', 'tracestate'),
    ],
];
