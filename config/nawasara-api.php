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
    // Rem per IP SEBELUM autentikasi (ketiga jalur: nws_, warga, staf)
    // -------------------------------------------------------------------------
    // Audit keamanan 15 Oktober 2026, temuan S14: tanpa rem ini token palsu
    // yang dikirim terus-menerus tidak tertahan apa pun, dan setiap 401
    // menulis satu baris api_access_logs. Lihat Support\AuthAbuseGuard.
    // Nilai 0 mematikan rem yang bersangkutan.
    'pre_auth' => [
        // Semua permintaan per IP per menit. LONGGAR dengan sengaja: ribuan
        // ponsel warga berbagi IP operator seluler (CGNAT).
        'per_ip_per_minute' => (int) env('NAWASARA_API_PREAUTH_PER_MINUTE', 600),

        // Penolakan 401 per IP per menit. Lewat dari ini, IP tersebut dijawab
        // 429 tanpa tokennya diperiksa sampai menitnya habis. Aplikasi yang
        // sah hampir tidak pernah ditolak, jadi angka ini aman jauh lebih kecil.
        'failures_per_ip_per_minute' => (int) env('NAWASARA_API_PREAUTH_FAILURES_PER_MINUTE', 60),

        // Berapa penolakan per IP per menit yang ditulis ke api_access_logs.
        // Sisanya tidak dicatat; 0 = tidak mencatat penolakan sama sekali.
        'denial_logs_per_ip_per_minute' => (int) env('NAWASARA_API_DENIAL_LOGS_PER_MINUTE', 10),
    ],

    // -------------------------------------------------------------------------
    // Audit log retention
    // -------------------------------------------------------------------------
    // Scheduled job prune row api_access_logs lebih tua dari ini (hari).
    'log_retention_days' => env('NAWASARA_API_LOG_RETENTION_DAYS', 90),

    // -------------------------------------------------------------------------
    // Autentikasi WARGA — JWT Keycloak
    // -------------------------------------------------------------------------
    // Jalur KEDUA, berdampingan dengan token `nws_`. Dipakai aplikasi ponsel
    // (puluhan ribu warga) yang tidak bisa memakai token statis: IP-nya
    // berpindah, tidak mengirim Origin, dan APK-nya dapat dibongkar.
    //
    // Verifikasi dilakukan LOKAL memakai kunci publik Keycloak — Keycloak
    // tidak berada di jalur request, sehingga ia lambat atau restart tidak
    // ikut menjatuhkan API.
    'staff' => [
        // Realm PEGAWAI — berbeda dari realm warga. Panel admin (Next.js)
        // memakai jalur ini; aplikasi warga memakai 'citizen' di atas.
        //
        // Keduanya sengaja dipisah: kunci penanda tangan, daftar client, dan
        // umur token realm pegawai tidak sama dengan realm warga. Token warga
        // yang dikirim ke endpoint staf akan gagal pada pemeriksaan issuer —
        // dan memang itu yang diinginkan.
        'base_url' => env('NAWASARA_STAFF_KC_URL', 'https://kisara.ponorogo.go.id'),
        'realm' => env('NAWASARA_STAFF_KC_REALM', 'asn-productions'),

        // Client panel. Dikosongkan = menerima semua client dalam realm
        // pegawai — TIDAK disarankan di sini: realm pegawai dipakai banyak
        // aplikasi lain (13 per Oktober 2026), dan tanpa daftar ini token dari
        // aplikasi mana pun akan diterima sebagai token panel.
        //
        // Audit keamanan 15 Oktober 2026, temuan S12. Daftar kosong TIDAK
        // dijadikan penolakan bawaan, karena produksi yang belum mengisi env
        // ini akan langsung menolak seluruh panel. Sebagai gantinya verifier
        // menulis peringatan sekali per proses, dan `enforce_allowed_clients`
        // tersedia untuk menolak bila daftarnya kosong.
        'allowed_clients' => array_filter(explode(',', (string) env(
            'NAWASARA_STAFF_KC_CLIENTS',
            ''
        ))),

        // true = daftar client KOSONG berarti tolak semua token (fail-closed).
        // Nyalakan setelah NAWASARA_STAFF_KC_CLIENTS terisi dan terbukti benar.
        'enforce_allowed_clients' => (bool) env('NAWASARA_STAFF_KC_ENFORCE_CLIENTS', false),

        'jwks_ttl' => (int) env('NAWASARA_STAFF_JWKS_TTL', 3600),
    ],

    'citizen' => [
        // Harus sama persis dengan realm yang menerbitkan token. Claim `iss`
        // dicocokkan dengan "<base_url>/realms/<realm>"; realm lain di server
        // Keycloak yang sama akan DITOLAK meski tanda tangannya sah.
        'base_url' => env('NAWASARA_CITIZEN_KC_URL', 'https://kisara.ponorogo.go.id'),
        'realm' => env('NAWASARA_CITIZEN_KC_REALM', 'ponorogo-citizen'),

        // Client yang tokennya diterima. Kosongkan untuk menerima semua client
        // dalam realm — issuer sudah menyempitkan asalnya ke satu realm.
        // Diperiksa terhadap `azp` MAUPUN `aud`: Keycloak sering menaruh nama
        // client di `azp` dan "account" di `aud`, sehingga memeriksa `aud`
        // saja akan menolak token yang sebenarnya sah.
        'allowed_clients' => array_filter(explode(',', (string) env(
            'NAWASARA_CITIZEN_KC_CLIENTS',
            'pramana-mobile'
        ))),

        // Lihat catatan yang sama di cabang 'staff'. Daftar warga sudah terisi
        // secara bawaan, jadi ini hanya berpengaruh bila env-nya dikosongkan.
        'enforce_allowed_clients' => (bool) env('NAWASARA_CITIZEN_KC_ENFORCE_CLIENTS', false),

        // TTL cache kunci publik (detik). Panjang karena kunci Keycloak jarang
        // berganti; saat rotasi terjadi, kegagalan pencocokan kunci memicu satu
        // kali segar-ulang otomatis (lihat CitizenJwtVerifier).
        'jwks_ttl' => (int) env('NAWASARA_CITIZEN_JWKS_TTL', 3600),

        // Batas permintaan per warga per menit, dikunci pada `sub`.
        // ⚠️ Ini batas TRANSPORT, bukan aturan bisnis. "Maksimal 5 laporan per
        // hari" ditegakkan di nawasara/aspirations, bukan di sini.
        'rate_limit_per_minute' => (int) env('NAWASARA_CITIZEN_RATE_PER_MINUTE', 60),
    ],

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
