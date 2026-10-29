# nawasara/api

Public REST API plumbing for the Nawasara framework.

This package provides the **infrastructure**: tokens, scopes, signed URLs, and an audit log. Domain packages (cctv, wifi, and so on) provide **their own endpoints** (routes, controllers, transformers). This package knows nothing about what a Camera or a WifiPoint is.

## What lives here

- `ApiToken`, `ApiTokenScope`, and `ApiAccessLog` (models plus migrations)
- `TokenManager`: generate, verify (plaintext to hash lookup), revoke
- `StreamUrlSigner`: HMAC-signed URLs for the stream proxy endpoint (Nginx `auth_request`)
- `ScopeRegistry`: an in-code registry of the available scopes
- Middleware: `api.auth`, `scope:<name>`, `api.log`
- Meta endpoints: `/api/v1/me`, `/api/v1/scopes`
- The `nawasara-api:prune-logs` command (scheduled daily)

## Usage from a domain package

In the domain package's service provider (for example `CctvServiceProvider`):

```php
use Nawasara\Api\Facades\Api;

public function boot(): void
{
    // Register the scope only if nawasara/api is installed. If it is not,
    // skip it; the domain package still works without a public API.
    if (class_exists(Api::class)) {
        Api::registerScope('cctv.camera.read', 'List + detail kamera publik.');
        Api::registerScope('cctv.camera.stream', 'Generate signed stream URL.');
    }

    // Load the domain's api.php routes (mounted at prefix /api/v1/cctv).
    Route::prefix('api/v1/cctv')
        ->middleware(['api', 'api.auth', 'api.log'])
        ->group(__DIR__.'/../routes/api.php');
}
```

In the domain package's `routes/api.php`:

```php
Route::get('/cameras', [CameraController::class, 'index'])
    ->middleware('scope:cctv.camera.read');

Route::get('/cameras/{slug}/stream', [CameraController::class, 'stream'])
    ->middleware('scope:cctv.camera.stream');
```

## Token format

Plaintext: `nws_<40 random url-safe chars>` (44 characters total, similar to a GitHub PAT). The `nws_` prefix helps GitHub's secret scanner detect a token if it leaks into a commit.

Stored in the database: the **SHA-256 hash** of the plaintext (column `token_hash`), plus the first 8 characters of the plaintext (column `token_prefix`) for visual identification in the list UI. The plaintext is **never** stored. It is shown once when generated and gone afterwards.

## Stream URL signing

The CCTV proxy-mode workflow:

```
Client → GET /api/v1/cctv/cameras/cam-01/stream
         Authorization: Bearer nws_xxx

Laravel verify token + scope cctv.camera.stream
        → generate signed URL via StreamUrlSigner:
          sig = HMAC-SHA256(slug + exp, APP_KEY)
          exp = unix timestamp + TTL (5 min default)

Response:
{
  "stream_url": ".../api/v1/cctv/stream/cam-01?sig=abc&exp=1234567890",
  "mode": "mse",
  "expires_at": "2026-05-16T10:30:00Z"
}

Client → connect ke stream_url

Nginx auth_request → /api/v1/cctv/stream/verify?sig=&exp=
                     (verify-only endpoint, return 200/403)

Nginx proxy_pass → http://go2rtc:1984/api/ws?src=cam-01
                   (kalau auth_request 200)
```

The implementation lives in the domain package (`nawasara/cctv` M3).

## Keycloak JWT paths (`api.citizen`, `api.staff`)

Besides `nws_` tokens there are two JWT paths, verified locally against the realm's JWKS: `api.citizen` (citizen realm, mobile app) and `api.staff` (employee realm, admin panel). Both accept **access tokens only**: the `typ` claim must be `Bearer`, so Keycloak ID tokens and refresh tokens are rejected even though they carry a valid signature and issuer (security audit 15 October 2026, finding R1).

### Environment

| Variable | Default | Meaning |
|---|---|---|
| `NAWASARA_STAFF_KC_URL` | `https://kisara.ponorogo.go.id` | Keycloak base URL for the employee realm |
| `NAWASARA_STAFF_KC_REALM` | `asn-productions` | Employee realm |
| `NAWASARA_STAFF_KC_CLIENTS` | *(empty)* | Comma-separated client ids whose tokens are accepted on `api.staff`, matched against `azp` and `aud` |
| `NAWASARA_STAFF_KC_ENFORCE_CLIENTS` | `false` | `true` = an empty client list rejects every staff token (fail-closed) |
| `NAWASARA_CITIZEN_KC_CLIENTS` | `pramana-mobile` | Same, for `api.citizen` |
| `NAWASARA_CITIZEN_KC_ENFORCE_CLIENTS` | `false` | Same, for `api.citizen` |

**Set `NAWASARA_STAFF_KC_CLIENTS` in every environment.** The employee realm serves many applications, and with an empty list a token issued to *any* of them is accepted as a panel token (finding S12). An empty list is not rejected by default, because doing so would lock the panel out of a deployment that has not set the variable yet; instead the verifier logs a warning once per process. Once the list is set and verified (check the `azp` claim of a real panel token), turn on `NAWASARA_STAFF_KC_ENFORCE_CLIENTS=true`.

### Staff without a `users` row (`api.staff.identity`)

`api.staff` maps the token to a local `users` row and answers 403 `not_registered` when there is none. That is right for the panel, but most civil servants never open the panel, so a service for *every* ASN (the ASN account portal) cannot use it.

`api.staff.identity` runs exactly the same token checks (it extends `AuthenticateStaffJwt`), then only sets the `staff_sub` and `staff_claims` request attributes. It never calls `Auth::setUser()`, even when a `users` row exists: an account endpoint must not inherit the panel's Spatie permissions. Endpoints behind it take the identity from `staff_sub`, never from a parameter.

### Per-route guards

Put these **after** one of the JWT middlewares:

| Alias | Example | Effect |
|---|---|---|
| `api.client` | `api.client:asn-portal` | Only tokens whose `azp` is one of the listed clients. 403 `client_not_allowed` otherwise; no parameter rejects everything |
| `api.recent-auth` | `api.recent-auth:300` | Only logins newer than N seconds (default 300), by the `auth_time` claim. 401 `reauth_required` with `max_age`; the caller re-authenticates with `max_age=0` and retries |

Why `api.client` checks **`azp` only** while the verifier's `allowed_clients` also accepts `aud`: the employee realm installs audience mappers that put other clients' names into `aud`, so a token issued to a different application can carry the portal's name in `aud`. `azp` is the client that actually requested the token.

`api.recent-auth` treats a token **without** `auth_time` as stale. Keycloak 25+ puts it in the access token through the `basic` client scope; a client without that scope will always be asked to sign in again, and the fix is the client configuration, not this middleware.

## Pre-auth rate limit

All three auth middlewares (`api.auth`, `api.citizen`, `api.staff`) start with a per-IP limiter (`Support\AuthAbuseGuard`) before any token is read (finding S14). It lives inside the middleware, not in each route group, so every package that uses these aliases is covered without changes.

| Variable | Default | Meaning |
|---|---|---|
| `NAWASARA_API_PREAUTH_PER_MINUTE` | `600` | All requests per IP per minute. Deliberately loose: many phones share one carrier IP (CGNAT) |
| `NAWASARA_API_PREAUTH_FAILURES_PER_MINUTE` | `60` | 401 responses per IP per minute; above this the IP gets `429` without its token being checked |
| `NAWASARA_API_DENIAL_LOGS_PER_MINUTE` | `10` | Denials per IP per minute written to `api_access_logs`; the rest are dropped. `0` = log none |

`0` disables the respective limit. The `429` body uses the usual shape: `{"error": {"code": "too_many_requests", "message": "..."}}` with a `Retry-After` header. The per-citizen limiter `throttle:nawasara-citizen` (keyed by `sub`) still runs after authentication.
