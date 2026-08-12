<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Nawasara\Api\Models\ApiAccessLog;
use Nawasara\Api\Services\CitizenJwtVerifier;
use Symfony\Component\HttpFoundation\Response;

/**
 * Autentikasi permintaan WARGA memakai JWT Keycloak.
 *
 * BERDAMPINGAN dengan AuthenticateApiToken, bukan menggantikannya. Nawasara
 * melayani dua jenis pemanggil yang sifatnya berbeda:
 *
 *   Sistem tepercaya  → `nws_…`      → AuthenticateApiToken (jalur lama)
 *   Warga             → JWT Keycloak → middleware ini
 *
 * Sengaja DUA jalur terpisah, bukan satu middleware yang mendeteksi jenis
 * token lalu bercabang. Bentuk bercabang terlihat lebih rapi, tetapi
 * menjadikan satu titik yang bila salah akan menjatuhkan Gasta dan integrasi
 * lain sekaligus. Rute warga memakai alias `api.citizen`; rute lama tidak
 * disentuh sama sekali.
 *
 * Mengapa token `nws_` tidak dapat dipakai aplikasi ponsel: ia mengandalkan
 * daftar IP, daftar Origin, dan kerahasiaan token — tidak satu pun berlaku
 * untuk puluhan ribu ponsel warga yang IP-nya berpindah, tidak mengirim
 * Origin, dan APK-nya dapat dibongkar. Uraian lengkap di
 * docs/plan/plan-ponorogo-hub-sso.md bagian 5.
 */
class AuthenticateCitizenJwt
{
    public function __construct(
        protected CitizenJwtVerifier $verifier,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $token = $this->extractToken($request);

        if ($token === null) {
            return $this->deny($request, 'missing_token',
                'Token tidak ditemukan. Kirim lewat header Authorization: Bearer <token>.');
        }

        // Token `nws_` yang nyasar ke rute warga ditolak dengan pesan yang
        // MENJELASKAN, bukan sekadar "tidak valid". Ini kekeliruan yang wajar
        // terjadi saat integrasi, dan tanpa petunjuk ini pemanggil akan
        // menghabiskan waktu mengira tokennya rusak.
        if (str_starts_with($token, 'nws_')) {
            return $this->deny($request, 'wrong_token_type',
                'Endpoint ini untuk warga dan memerlukan JWT Keycloak. Token nws_ dipakai pada endpoint sistem.');
        }

        $claims = $this->verifier->verify($token);

        if ($claims === null) {
            return $this->deny($request, 'invalid_token',
                'Token tidak valid atau sudah kedaluwarsa. Silakan masuk kembali.');
        }

        // `sub` adalah penanggung identitas warga di seluruh Nawasara. Ia tidak
        // pernah berubah meski warga mengganti surel atau menautkan Google —
        // karena itu ia, bukan email/username, yang dipakai menautkan data.
        // Lihat commit fa37d75: pencocokan lewat string pernah putus diam-diam.
        $request->attributes->set('citizen_sub', $claims['sub']);
        $request->attributes->set('citizen_claims', $claims);

        return $next($request);
    }

    /**
     * Ekstrak JWT dari header Authorization.
     *
     * Hanya Bearer — X-API-Key sengaja TIDAK didukung di sini. Header itu milik
     * konvensi token sistem; menerimanya untuk JWT hanya mengaburkan batas
     * antara dua jalur yang sengaja dipisah.
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

    /**
     * Tolak + catat ke ApiAccessLog.
     *
     * Dicatat supaya penolakan warga tetap dapat ditelusuri — tetapi
     * `token_id` null, karena tidak ada baris ApiToken yang bersangkutan.
     *
     * ⚠️ Volume log di sini jauh lebih besar daripada jalur `nws_`: puluhan
     * ribu warga, bukan segelintir sistem. Kebijakan retensi
     * (`PruneAccessLogsCommand`) perlu ditinjau sebelum peluncuran, kalau tidak
     * tabelnya tumbuh tanpa batas.
     */
    protected function deny(Request $request, string $code, string $message): Response
    {
        try {
            ApiAccessLog::create([
                // null: tidak ada baris ApiToken untuk warga. Kolomnya memang
                // nullable — lihat migrasi.
                'api_token_id' => null,
                'method' => $request->method(),
                // Dipotong 512 seperti jalur nws_: kolomnya string(512), dan
                // path panjang akan membuat INSERT gagal, sehingga penolakan
                // yang seharusnya tercatat malah hilang.
                'path' => substr($request->path(), 0, 512),
                'status' => 401,
                'kind' => ApiAccessLog::KIND_API,
                'ip' => $request->ip(),
                'user_agent' => substr((string) $request->userAgent(), 0, 512),
            ]);
        } catch (\Throwable) {
            // Kegagalan mencatat log TIDAK boleh menjatuhkan permintaan.
            // Penolakannya sendiri lebih penting daripada catatannya.
        }

        return response()->json([
            'error' => [
                'code' => $code,
                'message' => $message,
            ],
        ], 401);
    }
}
