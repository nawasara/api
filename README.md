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
