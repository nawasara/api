<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Nawasara\Api\Models\ApiAccessLog;
use Nawasara\Api\Services\StaffJwtVerifier;
use Symfony\Component\HttpFoundation\Response;

/**
 * Autentikasi permintaan STAF (ASN) memakai JWT realm `asn-productions`.
 *
 * Jalur KETIGA, berdampingan dengan dua yang sudah ada:
 *
 *   Sistem tepercaya → `nws_…`           → AuthenticateApiToken   (`api.auth`)
 *   Warga            → JWT realm warga   → AuthenticateCitizenJwt (`api.citizen`)
 *   Staf ASN         → JWT realm pegawai → middleware ini         (`api.staff`)
 *
 * Dibuat karena panel admin pindah ke Next.js: panel tidak lagi berjalan di
 * dalam Laravel dengan sesi Keycloak yang sudah ditangani `nawasara/core`,
 * melainkan memanggil API dari domain lain dengan membawa token.
 *
 * ── Yang membedakannya dari jalur warga ──────────────────────────────────
 *
 * Warga cukup dikenali lewat `sub`; datanya memang bersandar pada `sub` itu.
 * Staf TIDAK cukup begitu — seluruh otorisasi Nawasara (Spatie permission,
 * `ScopedToOpd`, kepemilikan OPD) bersandar pada baris `users`. Karena itu
 * middleware ini MEMETAKAN token ke User lokal dan menyalakan `Auth::setUser()`,
 * sehingga `$request->user()`, `can()`, dan `auth()->id()` bekerja persis
 * seperti pada panel Livewire.
 *
 * Tanpa pemetaan itu, setiap endpoint staf harus menerjemahkan `sub` menjadi
 * user sendiri-sendiri — dan yang lupa melakukannya akan diam-diam melewati
 * pemeriksaan izin.
 *
 * ⚠️ Staf yang tokennya sah tetapi TIDAK punya baris `users` ditolak, bukan
 * dibuatkan otomatis. Membuat user diam-diam berarti siapa pun yang punya akun
 * di realm pegawai — termasuk pegawai dinas lain yang tak ada urusan dengan
 * aplikasi ini — otomatis mendapat pijakan di dalam sistem. Penambahan staf
 * dilakukan lewat panel, dengan peran yang ditetapkan sadar.
 */
class AuthenticateStaffJwt
{
    public function __construct(
        protected StaffJwtVerifier $verifier,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            return $this->deny($request, 'missing_token',
                'Token tidak ditemukan. Kirim lewat header Authorization: Bearer <token>.');
        }

        // Pesan yang MENJELASKAN, bukan sekadar "tidak valid" — pola yang sama
        // dengan jalur warga. Ketiga jalur mudah tertukar saat integrasi, dan
        // tanpa petunjuk ini pemanggil akan mengira tokennya rusak.
        if (str_starts_with($token, 'nws_')) {
            return $this->deny($request, 'wrong_token_type',
                'Endpoint ini untuk staf dan memerlukan JWT Keycloak. Token nws_ dipakai pada endpoint sistem.');
        }

        $claims = $this->verifier->verify($token);

        if ($claims === null) {
            return $this->deny($request, 'invalid_token',
                'Token tidak valid atau sudah kedaluwarsa. Silakan masuk kembali.');
        }

        $user = $this->resolveUser($claims);

        if ($user === null) {
            // 403, bukan 401: tokennya SAH, orangnya saja yang belum terdaftar
            // di aplikasi ini. Menjawab 401 akan membuat panel mengira sesinya
            // kedaluwarsa lalu memaksa masuk ulang tanpa henti.
            return $this->deny($request, 'not_registered',
                'Akun Anda belum terdaftar di aplikasi ini. Hubungi admin untuk didaftarkan.',
                403);
        }

        // Menyalakan pengguna untuk permintaan ini saja — tanpa sesi, tanpa
        // cookie. Sesudah baris ini, `can()` dan `ScopedToOpd` bekerja seperti
        // biasa.
        Auth::setUser($user);

        $request->attributes->set('staff_sub', $claims['sub']);
        $request->attributes->set('staff_claims', $claims);

        return $next($request);
    }

    /**
     * Petakan claim ke baris `users`.
     *
     * Dicocokkan lewat `keycloak_id` (= `sub`), BUKAN email atau username.
     * `sub` tidak berubah ketika pegawai berganti nama atau surel; pencocokan
     * lewat string pernah putus diam-diam (lihat commit fa37d75).
     */
    protected function resolveUser(array $claims): ?object
    {
        $sub = $claims['sub'] ?? null;

        if (! is_string($sub) || $sub === '') {
            return null;
        }

        $model = config('auth.providers.users.model', \App\Models\User::class);

        return $model::query()->where('keycloak_id', $sub)->first();
    }

    /**
     * Ekstrak JWT dari header Authorization.
     *
     * Hanya Bearer — X-API-Key milik konvensi token sistem dan sengaja tidak
     * diterima di sini.
     */
    protected function extractToken(Request $request): ?string
    {
        $auth = $request->header('Authorization');

        if (! is_string($auth) || ! str_starts_with($auth, 'Bearer ')) {
            return null;
        }

        $candidate = trim(substr($auth, 7));

        return $candidate === '' ? null : $candidate;
    }

    /** Tolak + catat, dengan pola yang sama seperti jalur warga. */
    protected function deny(Request $request, string $code, string $message, int $status = 401): Response
    {
        try {
            ApiAccessLog::create([
                'api_token_id' => null,
                'method' => $request->method(),
                'path' => substr($request->path(), 0, 512),
                'status' => $status,
                'kind' => ApiAccessLog::KIND_API,
                'ip' => $request->ip(),
                'user_agent' => substr((string) $request->userAgent(), 0, 512),
            ]);
        } catch (\Throwable) {
            // Gagal mencatat tidak boleh menjatuhkan permintaan — penolakannya
            // lebih penting daripada catatannya.
        }

        return response()->json([
            'error' => [
                'code' => $code,
                'message' => $message,
            ],
        ], $status);
    }
}
