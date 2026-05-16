<?php

return [
    // -------------------------------------------------------------------------
    // Token format
    // -------------------------------------------------------------------------
    // Plaintext token format: <prefix> + '_' + N random url-safe chars.
    // Prefix bantu secret-scanner GitHub detect kalau bocor ke commit.
    // Total panjang plaintext = strlen(prefix) + 1 + body_length.
    'token' => [
        'prefix' => env('NAWASARA_API_TOKEN_PREFIX', 'nws'),

        // Panjang body random. 40 char = ~240 bit entropy, cukup untuk
        // hindari brute-force online.
        'body_length' => 40,

        // Berapa karakter pertama plaintext yang disimpan plaintext di DB
        // (kolom token_prefix) untuk identifikasi visual di list. Sisanya
        // di-hash. 8 char = collision negligible tapi tidak ungkap rahasia.
        'visible_prefix_length' => 8,

        // Throttle update last_used_at: kalau token dipakai burst, jangan
        // UPDATE row tiap request — cukup sekali per interval ini (detik).
        'last_used_throttle_seconds' => 60,
    ],

    // -------------------------------------------------------------------------
    // Stream URL signing (HMAC)
    // -------------------------------------------------------------------------
    // Dipakai endpoint domain (mis. CCTV stream) untuk generate signed URL
    // yang Nginx `auth_request` validate sebelum proxy ke service internal.
    // Signing key: APP_KEY Laravel. TTL pendek (default 5 menit) supaya
    // kebocoran URL terbatas.
    'stream_url' => [
        // TTL signed URL dalam detik. Pendek = aman, tapi client harus
        // request stream URL baru kalau session lama. 5 menit kompromi
        // wajar untuk live-view yang biasanya session pendek-menengah.
        'ttl_seconds' => env('NAWASARA_API_STREAM_TTL', 300),

        // Algoritma HMAC. SHA-256 cukup; jangan pakai MD5/SHA-1.
        'algorithm' => 'sha256',
    ],

    // -------------------------------------------------------------------------
    // Rate limit per token (default; nanti bisa per-token override)
    // -------------------------------------------------------------------------
    'rate_limit' => [
        // Request per menit per token. Laravel throttle middleware.
        'per_minute' => env('NAWASARA_API_RATE_PER_MINUTE', 60),
    ],

    // -------------------------------------------------------------------------
    // Audit log retention
    // -------------------------------------------------------------------------
    // Scheduled job prune row api_access_logs lebih tua dari ini (hari).
    'log_retention_days' => env('NAWASARA_API_LOG_RETENTION_DAYS', 90),

    // -------------------------------------------------------------------------
    // Route configuration
    // -------------------------------------------------------------------------
    'route' => [
        // Prefix base untuk semua endpoint API. Domain package mount sub-route
        // di bawah ini (mis. CCTV: /api/v1/cctv/...).
        'prefix' => env('NAWASARA_API_PREFIX', 'api/v1'),

        // Middleware group yang di-apply ke route API. 'api.auth' = auth token,
        // throttle = rate limit per token.
        'middleware' => ['api', 'api.auth'],
    ],
];
