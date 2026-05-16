# nawasara/api

Public REST API plumbing untuk framework Nawasara.

Package ini menyediakan **infrastruktur**: token + scope + signed URL +
audit log. Domain package (cctv, wifi, …) menyediakan **endpoint mereka
sendiri** (route, controller, transformer) — package ini tidak tahu apa
itu Camera atau WifiPoint.

## Yang ada di sini

- `ApiToken` + `ApiTokenScope` + `ApiAccessLog` (model + migration)
- `TokenManager` — generate, verify (by plaintext → hash lookup), revoke
- `StreamUrlSigner` — HMAC-signed URL untuk endpoint stream proxy (Nginx
  `auth_request`)
- `ScopeRegistry` — registry in-code untuk scope yang available
- Middleware: `api.auth`, `scope:<name>`, `api.log`
- Endpoint meta: `/api/v1/me`, `/api/v1/scopes`
- Command `nawasara-api:prune-logs` (scheduled harian)

## Pemakaian — domain package

Di service provider package domain (mis. `CctvServiceProvider`):

```php
use Nawasara\Api\Facades\Api;

public function boot(): void
{
    // Register scope kalau package nawasara/api terpasang. Kalau tidak,
    // skip — domain package tetap jalan tanpa API public.
    if (class_exists(Api::class)) {
        Api::registerScope('cctv.camera.read', 'List + detail kamera publik.');
        Api::registerScope('cctv.camera.stream', 'Generate signed stream URL.');
    }

    // Load route api.php domain (mount di prefix /api/v1/cctv).
    Route::prefix('api/v1/cctv')
        ->middleware(['api', 'api.auth', 'api.log'])
        ->group(__DIR__.'/../routes/api.php');
}
```

Di `routes/api.php` domain package:

```php
Route::get('/cameras', [CameraController::class, 'index'])
    ->middleware('scope:cctv.camera.read');

Route::get('/cameras/{slug}/stream', [CameraController::class, 'stream'])
    ->middleware('scope:cctv.camera.stream');
```

## Token format

Plaintext: `nws_<40 random url-safe chars>` (44 char total, mirip GitHub
PAT). Prefix `nws_` membantu secret scanner GitHub detect kalau bocor ke
commit.

Disimpan di DB: **hash SHA-256** dari plaintext (kolom `token_hash`),
plus 8 char pertama plaintext (kolom `token_prefix`) untuk identifikasi
visual di list UI. Plaintext **TIDAK** pernah disimpan — ditampilkan
sekali saat generate, hilang setelahnya.

## Stream URL signing

Workflow proxy mode CCTV:

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

Implementation detail di package domain (`nawasara/cctv` M3).
