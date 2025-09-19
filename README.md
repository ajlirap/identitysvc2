Laravel 12 IdentitySvc – Vendor‑Agnostic Scaffold
=================================================

Overview
- Facade + adapter pattern to front external IdPs (Azure AD B2C, Auth0, Okta, Keycloak).
- Includes auth endpoints, user lifecycle endpoints, local JWT validation middleware, and event stubs.

Quick Start
1) Create project and install deps

   - Create Laravel 12 app
     composer create-project laravel/laravel identitysvc "^12.0"
     cd identitysvc

   - Core deps
     composer require guzzlehttp/guzzle:^7.9 firebase/php-jwt:^6.10 psr/http-message:^2.0

   - Optional helpers
     composer require ramsey/uuid:^4.7 spatie/laravel-data:^4.6
     composer require monolog/monolog:^3

2) Copy scaffold files

   Copy from this repo’s `scaffold/` into your Laravel app root (preserve paths):
   - config/identity.php
   - app/Contracts/*
   - app/DTO/*
   - app/Support/ProviderFactory.php
   - app/Security/*
   - app/Http/Middleware/VerifyJwt.php
   - app/Http/Controllers/{AuthController,UsersController}.php
   - app/Providers/Adapters/** (B2C/Auth0/Okta/Keycloak)
   - app/Events/UserCreated.php (add more as needed)
   - routes/api.php (merge with your existing routes if present)

3) Env/config

   Append the contents of `scaffold/.env.example.additions` to your `.env` and `.env.example`.
   Update values for your selected vendor.

4) Wire middleware alias

   In app/Http/Kernel.php add:
     protected $middlewareAliases = [
       // ...
       'verify.jwt' => \App\Http\Middleware\VerifyJwt::class,
     ];

   Use it on routes or groups as needed.

5) AppServiceProvider

   app/Providers/AppServiceProvider.php -> register():
     // Identity adapters are auto-resolved by their constructors.

6) Basic policy stub (RBAC)

   app/Providers/AuthServiceProvider.php -> boot():
     Gate::define('idp.admin', function ($user, $claims) {
       $roles = $claims['roles'] ?? [];
       return in_array('idp.admin', $roles, true);
     });

7) L5-Swagger (optional)

   composer require darkaonline/l5-swagger:^9.0 --dev
   php artisan vendor:publish --provider "L5Swagger\L5SwaggerServiceProvider"

   config/l5-swagger.php (key bits):
     return [
       'default' => 'default',
       'documentations' => [
         'default' => [
           'api' => ['title' => 'IdentitySvc API'],
           'routes' => ['api' => 'api/docs'],
           'paths' => [
             'docs_json' => 'api-docs.json',
             'annotations' => [
               base_path('app/Http/Controllers'),
               base_path('app/DTO'),
             ],
           ],
         ],
       ],
     ];

   Generate and browse:
     php artisan l5-swagger:generate
     GET /api/docs

8) Optional admin plane split

   - Move admin routes to routes/admin.php and guard with an InternalAuth middleware.
   - Load conditionally in bootstrap/app.php when INTERNAL_PLANE=true.

Endpoints
- GET  /api/auth/login                -> returns authorize_url
- GET  /api/me (with bearer token)    -> returns profile
- GET  /api/admin/users               -> list users (admin)
- POST /api/admin/users               -> create user (admin)
- POST /api/admin/users/invite        -> invite user (admin)
- POST /api/admin/users/{id}/deactivate
- POST /api/admin/users/{id}/password-reset  (body: { newPassword })
- POST /api/users/validate-email     -> public email format/domain check (non-enumerating; optional CAPTCHA)
- POST /api/users/check-active       -> public-safe eligibility (non-enumerating; optional CAPTCHA)
  - Optional: set `EMAIL_REVEAL_EXISTENCE=true` to include `{ exists, active }` in the response and make `eligible` require an active account. Use with care to avoid user enumeration.
- POST /api/admin/users/check-active -> admin-only existence/active (JWT + role)

Azure AD B2C (OIDC sign-in)
- Required env:
  - `IDENTITY_VENDOR=b2c`
  - `B2C_DOMAIN` (host-only or full https URL, e.g., `contoso.b2clogin.com`)
  - `B2C_TENANT_ID` (tenant GUID or `contoso.onmicrosoft.com`; falls back to `B2C_TENANT` when blank)
  - `B2C_TENANT` (legacy identifier; still used for Graph calls and legacy hosts)
  - `B2C_POLICY_SIGNIN` (user flow, e.g., `B2C_1_signin`)
  - `B2C_CLIENT_ID` / `B2C_CLIENT_SECRET`
  - `B2C_REDIRECT_URI` (must match the reply URL registered with the policy)
  - Optional: `B2C_SCOPE` (defaults to `openid offline_access`), `B2C_USE_PKCE` (set true to require PKCE)
- Endpoint discovery defaults:
  - Unless you provide overrides, the service downloads `https://<B2C_DOMAIN>/<B2C_TENANT_ID>/<policy>/v2.0/.well-known/openid-configuration` on first use and caches the metadata per policy.
  - Discovery uses the exact domain and tenant segment you provide, so populate both values instead of relying on implicit string conversions.
  - You can force a specific metadata URL with `B2C_DISCOVERY_ENDPOINT` (supports a `{policy}` placeholder).
  - Manual overrides are still honored: set `B2C_AUTHORIZE_ENDPOINT`, `B2C_TOKEN_ENDPOINT`, `B2C_ISSUER`, or `B2C_JWKS_URI` if you need non-standard hosts.
- Troubleshooting tips:
  - A missing `access_token` in the callback usually means the policy rejected the request; inspect Azure's error payload before the array lookup.
  - Ensure the redirect URI in the Azure user flow matches `B2C_REDIRECT_URI` exactly (scheme/host/case).
  - If multiple policies share the same domain/tenant, provide the policy name in the authorize URL via `B2C_POLICY_SIGNIN` and configure additional policies with environment overrides as needed.

Azure AD B2C Graph Admin (vendor=b2c)
- Overview:
  - When `IDENTITY_VENDOR=b2c`, additional admin endpoints are available under `/api/admin/b2c/graph/*` and related paths to proxy Microsoft Graph for user lifecycle and MFA methods. These routes are not registered for other vendors.
- Required env for Graph:
  - `B2C_GRAPH_TENANT` (e.g., `yourtenant.onmicrosoft.com` or tenant GUID)
  - `B2C_GRAPH_CLIENT_ID`, `B2C_GRAPH_CLIENT_SECRET` (app with app permissions, admin-consented)
  - `B2C_GRAPH_SCOPE` (default: `https://graph.microsoft.com/.default`)
- Optional: `B2C_GRAPH_TOKEN_ENDPOINT` to override discovery
- Optional: `B2C_GRAPH_RAW_ROUTES` (default: true) to enable/disable exposure of raw Graph proxy routes. When false, only the vendor-agnostic Admin Users facade is available.
- Token endpoint discovery and v1/v2 handling:
  - If token endpoint is v1 (`.../oauth2/token`), service sends `resource=https://graph.microsoft.com`.
  - If v2 (`.../oauth2/v2.0/token`), service sends `scope=https://graph.microsoft.com/.default`.
  - If `B2C_GRAPH_TOKEN_ENDPOINT` is not set, the service fetches `/.well-known/openid-configuration` to discover `token_endpoint`.
- Admin Graph endpoints (bearerAuth):
  - Token and discovery
    - `POST /api/admin/b2c/graph/token` → client_credentials token for Graph
    - `GET  /api/admin/b2c/openid-configuration` → OIDC discovery for tenant
  - Users
    - `GET    /api/admin/b2c/graph/users/{id}` (optional `select` query for `$select`)
    - `GET    /api/admin/b2c/graph/users?mail=email@example.com` (filter by mail)
    - `POST   /api/admin/b2c/graph/users` (create)
    - `PATCH  /api/admin/b2c/graph/users/{id}` (partial update)
    - `DELETE /api/admin/b2c/graph/users/{id}` (delete)
    - List all via service adapter uses: `GET https://graph.microsoft.com/v1.0/users?%24filter%20all=null&$top=...` for unfiltered listing
  - Authentication methods (MFA)
    - Phone: `GET/POST/DELETE /api/admin/b2c/graph/users/{id}/authentication/phoneMethods` (DELETE supports `?methodId=` or deletes all)
    - Email: `GET/POST/DELETE /api/admin/b2c/graph/users/{id}/authentication/emailMethods` (DELETE supports `?methodId=` or deletes all)
    - All methods: `GET /api/admin/b2c/graph/users/{id}/authentication/methods`
    - Reset password via method: `POST /api/admin/b2c/graph/users/{id}/authentication/methods/{methodId}/resetPassword`
  - Misc
    - `POST /api/admin/b2c/graph/me/items/{id}/workbook/closeSession` (Excel workbook session)

Security and permissions
- Ensure your Azure AD app has the proper Graph application permissions (e.g., `User.ReadWrite.All`, `Directory.AccessAsUser.All` as applicable) and has admin consent.
- These endpoints are raw proxies; apply your own admin gating (e.g., network ACLs, internal auth) in addition to bearer token.

Tracing & Correlation IDs
- Middleware adds and propagates IDs on every request/response:
  - `X-Correlation-Id`: end-to-end correlation identifier (generated if missing).
  - `X-Request-Id`: per-request identifier for this hop.
  - `traceparent`/`tracestate`: W3C Trace Context headers (parsed/propagated; new span generated per hop).
- IDs are available via the service container and logging context as:
  - `app('correlation_id')`, `app('request_id')`, `app('trace_id')`, `app('span_id')`.
- Configure header names (optional) via env:
  - `TRACE_CORRELATION_HEADER`, `TRACE_REQUEST_HEADER`, `TRACE_TRACEPARENT_HEADER`, `TRACE_TRACESTATE_HEADER`.

Notes
- JWT validation uses Firebase/JWT and caches JWKS via Http + Cache. The validator uses JWK::parseKey for RSA keys.
- B2C adapter includes MS Graph client-credential calls for lifecycle. Ensure app permissions (User.ReadWrite.All or least privilege) are granted and admin-consented.
- You can set BFF cookies in AuthController instead of returning tokens.
- Consider rate limiting for password reset and admin endpoints, and idempotency keys for POST /api/admin/users.

Public email checks & CAPTCHA
- Purpose: Allow the UI to pre-check email format/domain without leaking whether an account exists.
- Public endpoints:
  - POST /api/users/validate-email ⇒ returns { validFormat, allowedDomain, mxValid }
  - POST /api/users/check-active ⇒ returns { eligible, validFormat, allowedDomain, message }
- Admin endpoint:
  - POST /api/admin/users/check-active ⇒ returns { exists, active, user } and requires a JWT with the admin role.
- Rate limiting (configured in AppServiceProvider):
  - validate-email: per IP 30/min, per email 60/min
  - check-active: per IP 20/min, per email 40/min
- CAPTCHA (optional):
  - Enable by setting CAPTCHA_ENABLED=true and supplying CAPTCHA_SECRET.
  - Supported providers: reCAPTCHA v3 (uses score) and Cloudflare Turnstile.
  - The UI must include a captcha token in the request body as { "captcha": "<token>" } when enabled.
  - Config keys are under identity.captcha in config/identity.php.

Environment variables (examples)
- Email validation (non-enumerating constraints):
  - EMAIL_ALLOWED_DOMAINS=example.com,contoso.com  # optional allow list (domains)
  - EMAIL_BLOCKED_DOMAINS=mailinator.com,tempmail.com  # optional deny list
  - EMAIL_VALIDATE_MX=false  # optional DNS MX/A check for domains
  - EMAIL_REVEAL_EXISTENCE=false  # if true, public /users/check-active also returns {exists,active}
- CAPTCHA (optional):
  - CAPTCHA_ENABLED=false
  - CAPTCHA_PROVIDER=recaptcha   # recaptcha|turnstile
  - CAPTCHA_SECRET=              # server-side secret
  - CAPTCHA_MIN_SCORE=0.5        # reCAPTCHA v3 only
  - CAPTCHA_RECAPTCHA_VERIFY_URL=https://www.google.com/recaptcha/api/siteverify
  - CAPTCHA_TURNSTILE_VERIFY_URL=https://challenges.cloudflare.com/turnstile/v0/siteverify

Tracing & Correlation IDs
- Middleware adds and propagates IDs on every request/response:
  - X-Correlation-Id: end-to-end correlation identifier (generated if missing).
  - X-Request-Id: per-request identifier for this hop.
  - traceparent/tracestate: W3C Trace Context headers (parsed/propagated; new span generated per hop).
- IDs are available via the service container and logging context as:
  - app('correlation_id'), app('request_id'), app('trace_id'), app('span_id').
- Configure header names (optional) via env:
  - TRACE_CORRELATION_HEADER, TRACE_REQUEST_HEADER, TRACE_TRACEPARENT_HEADER, TRACE_TRACESTATE_HEADER.
- Outbound propagation:
  - All Http:: calls automatically include correlation/request IDs and traceparent/tracestate for end-to-end tracing.

Logging
- HTTP logs are written to storage/logs/http-YYYY-MM-DD.log via the "http" channel.
- Set LOG_FORMAT=line for compact line logs (default in this scaffold).
- Prefix format (line mode):
  - [YYYY-MM-DD HH:MM:SS.mmm +TZ|LEV|<correlation> (<request>) <trace>/<span>|<env>] message {context}
- Example:
  - [2025-09-11 22:54:07.598 +00:00|INF|b75de4dd-... (e94789a0-...) 3b4c.../8a7e...|local] http.request {"method":"GET",...}

Testing examples (curl)
- Public check (no CAPTCHA):
  - Ensure CAPTCHA_ENABLED=false, then php artisan config:clear.
  - curl -X POST 'http://127.0.0.1:8000/api/users/check-active' -H 'Content-Type: application/json' -d '{"email":"user@example.com"}'
- Public check (with CAPTCHA):
  - Provide a valid client token in "captcha".
  - curl -X POST 'http://127.0.0.1:8000/api/users/check-active' -H 'Content-Type: application/json' -d '{"email":"user@example.com","captcha":"<CLIENT_TOKEN>"}'
- Admin check (JWT required):
  - curl -X POST 'http://127.0.0.1:8000/api/admin/users/check-active' -H 'Authorization: Bearer <ADMIN_JWT>' -H 'Content-Type: application/json' -d '{"email":"user@example.com"}'

CAPTCHA testing tips
- reCAPTCHA v3: add localhost/127.0.0.1 to allowed domains; fetch a token in the browser console using grecaptcha.execute(siteKey,{action:'check_active'}).
- Turnstile: use a minimal HTML page to render the widget and copy its token; or use Cloudflare test keys for local-only verification.
- After changing .env, run php artisan config:clear or restart to apply.

Public email checks & CAPTCHA
- Purpose: Allow the UI to pre-check email format/domain without leaking whether an account exists.
- Public endpoints:
  - POST /api/users/validate-email ⇒ returns { validFormat, allowedDomain, mxValid }
  - POST /api/users/check-active ⇒ returns { eligible, validFormat, allowedDomain, message }
- Admin endpoint:
  - POST /api/admin/users/check-active ⇒ returns { exists, active, user } and requires a JWT with the admin role.
- Rate limiting (configured in AppServiceProvider):
  - validate-email: per IP 30/min, per email 60/min
  - check-active: per IP 20/min, per email 40/min
- CAPTCHA (optional):
  - Enable by setting CAPTCHA_ENABLED=true and supplying CAPTCHA_SECRET.
  - Supported providers: reCAPTCHA v3 (uses score) and Cloudflare Turnstile.
  - The UI must include a captcha token in the request body as { "captcha": "<token>" } when enabled.
  - Config keys are under identity.captcha in config/identity.php.

Environment variables (examples)
- Email validation (non-enumerating constraints):
  - EMAIL_ALLOWED_DOMAINS=example.com,contoso.com  # optional allow list (domains)
  - EMAIL_BLOCKED_DOMAINS=mailinator.com,tempmail.com  # optional deny list
  - EMAIL_VALIDATE_MX=false  # optional DNS MX/A check for domains
- CAPTCHA (optional):
  - CAPTCHA_ENABLED=false
  - CAPTCHA_PROVIDER=recaptcha   # recaptcha|turnstile
  - CAPTCHA_SECRET=              # server-side secret
  - CAPTCHA_MIN_SCORE=0.5        # reCAPTCHA v3 only
  - CAPTCHA_RECAPTCHA_VERIFY_URL=https://www.google.com/recaptcha/api/siteverify
  - CAPTCHA_TURNSTILE_VERIFY_URL=https://challenges.cloudflare.com/turnstile/v0/siteverify

Local Testing with Keycloak
- Prereqs: Docker Desktop installed and running.
- Start Keycloak:
  - `cd identitysvc`
  - `docker compose -f docker-compose.keycloak.yml up -d`
  - Admin UI at `http://localhost:8081` (user: `admin`, pass: `admin`).
- Create realm `myrealm`:
  - Log into Keycloak → top-left realm selector → Create realm → Name `myrealm` → Create.
- Create OIDC client:
  - Clients → Create → Client ID: `identitysvc-client` → Next
  - Enable Standard Flow; turn ON “Client authentication” (confidential) → Save
  - Set Valid redirect URIs: `http://localhost:8000/api/auth/callback`
  - Credentials tab → copy Client Secret.
  - Optional (for CLI token testing): Client Settings → Capability config → enable “Direct access grants”.
- Enable service account for admin APIs (recommended):
  - Clients → identitysvc-client → Settings → Service accounts enabled: ON → Save
  - Clients → identitysvc-client → Service account roles → Assign role →
    - Realm Roles: add `view-users`
    - Client Roles (realm-management): add `manage-users`, `view-users` (and others you need)
  - This allows the microservice to obtain an admin token via client credentials (no password grant required).
- Configure IdentitySvc env:
  - Copy `identitysvc/.env.keycloak.example` to `.env` and fill secrets:
    - `IDENTITY_VENDOR=keycloak`
    - `KC_REALM=myrealm`
    - `KC_BASE_URL=http://localhost:8081`
    - `KC_CLIENT_ID=identitysvc-client`
    - `KC_CLIENT_SECRET=<from Credentials tab>`
    - `KC_REDIRECT_URI=http://localhost:8000/api/auth/callback`
    - `KC_ISSUER=http://localhost:8081/realms/myrealm`
    - `KC_JWKS_URI=http://localhost:8081/realms/myrealm/protocol/openid-connect/certs`
    - `KC_ADMIN_USER=svc-admin`
    - `KC_ADMIN_PASS=<your password>`
- Run IdentitySvc:
  - `cd identitysvc`
  - `php artisan serve`
- Smoke test auth facade:
  - Get authorize URL: `curl http://localhost:8000/api/auth/login`
- Quick token (password grant, if enabled):
    - `curl -s -X POST http://localhost:8081/realms/myrealm/protocol/openid-connect/token \`
      `-d grant_type=password -d client_id=identitysvc-client -d client_secret=<secret> \`
      `-d username=<realm-user> -d password=<password> -d scope="openid profile email"`
    - Copy `access_token` from the response.
  - Me endpoint: `curl -H "Authorization: Bearer <access_token>" http://localhost:8000/api/me`
- Smoke test lifecycle (admin):
  - Create user: `curl -X POST http://localhost:8000/api/admin/users -H "Content-Type: application/json" \`
    `-d '{"email":"test@example.com","givenName":"Test","familyName":"User","invite":false}'`
  - Invite user: `curl -X POST http://localhost:8000/api/admin/users/invite -H "Content-Type: application/json" \`
    `-d '{"email":"invitee@example.com","givenName":"Invitee","familyName":"User"}'`
  - Deactivate: `curl -X POST http://localhost:8000/api/admin/users/<id>/deactivate`
  - Activate: `curl -X POST http://localhost:8000/api/admin/users/<id>/activate`
- Tear down:
  - `docker compose -f docker-compose.keycloak.yml down -v`

Keycloak Admin API configuration (Required)
- Enable service account on your confidential client (`KC_CLIENT_ID`).
  - Clients → your client → Settings → Service accounts enabled: ON → Save
- Grant realm-management roles to the service account:
  - Clients → your client → Service account roles → Assign role → Client roles: `realm-management`
  - Add at minimum:
    - `view-users` and `query-users` (required to list users)
    - `manage-users` (required for create/activate/deactivate/reset)
    - Optional: `query-groups` if you plan to inspect groups
- Required environment variables for this service:
  - `IDENTITY_VENDOR=keycloak`
  - `KC_BASE_URL` (e.g., `http://localhost:8081`)
  - `KC_REALM` (e.g., `myrealm`)
  - `KC_CLIENT_ID` / `KC_CLIENT_SECRET` (confidential client in that realm)
  - `KC_ISSUER` and `KC_JWKS_URI` should match your realm (used for JWT validation of public endpoints)

Expected admin token (reference)
- The admin client-credential access token (obtained by this service) should include:
  - `aud` containing `realm-management` (and typically your client ID and `account`)
  - `resource_access.realm-management.roles` including `manage-users`, `view-users`, `query-users` (and optional `query-groups`)
  - `iss` equal to `KC_ISSUER` (e.g., `http://localhost:8081/realms/myrealm`)

Quick verify with curl
```
export KC_BASE_URL=http://localhost:8081
export KC_REALM=myrealm
export KC_CLIENT_ID=identitysvc-client
export KC_CLIENT_SECRET=...

# Get client-credential token
TOK=$(curl -s -X POST "$KC_BASE_URL/realms/$KC_REALM/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id=$KC_CLIENT_ID -d client_secret=$KC_CLIENT_SECRET | jq -r .access_token)

# Call Admin API (should be 200)
curl -i -H "Authorization: Bearer $TOK" "$KC_BASE_URL/admin/realms/$KC_REALM/users?first=0&max=1"
```

Troubleshooting 403 (Keycloak)
- Ensure roles are assigned to the service account under the same realm as `KC_REALM`.
- Confirm the token’s `resource_access.realm-management.roles` contains `view-users`/`query-users` (for GET) and `manage-users` (for mutations).
- Check that `KC_BASE_URL` points to the correct Keycloak base and is reachable from the service.
- Inspect `storage/logs/laravel.log` for upstream error payloads to pinpoint missing privileges.

API Docs
- UI: GET http://localhost:8000/api/docs
- Spec (L5-Swagger): GET http://localhost:8000/api/documentation
- If you prefer a static file, copy `storage/api-docs/api-docs.json` to `public/api-docs.json` and adjust `resources/views/api-docs.blade.php` accordingly.

Auth Flow (PKCE)
- Login: GET `/api/auth/login` returns `authorize_url` that includes `state` and PKCE `code_challenge` (S256).
- Storage: The corresponding `code_verifier` is stored server‑side in Cache under `pkce:{state}` for 10 minutes.
- Callback: Keycloak redirects to your `KC_REDIRECT_URI` with `code` and `state`. The service reads the verifier via `state` and exchanges the code at the token endpoint.
- Config knobs:
  - Leeway and JWKS TTL in `config/identity.php` → `identity.common`.
  - Cache store controls where PKCE verifiers are stored (`CACHE_STORE` in `.env`). Ensure the cache store is available.

Troubleshooting Redirect URIs (Keycloak)
- Enter raw URL without quotes or backticks: `http://localhost:8000/api/auth/callback`.
- If validation fails, try `http://127.0.0.1:8000/api/auth/callback` or `http://localhost:8000/*` during local testing.
- Check Realm Settings → Login → Require SSL. For local HTTP, set to “none” or “external requests”.
- Add Web origins: `http://localhost:8000` (or `+`) to avoid CORS issues with hosted UIs.
- If using our compose mapping, Keycloak runs on 8081; this does not affect the redirect back to port 8000.
