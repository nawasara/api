<?php

namespace Nawasara\Api\Http\Middleware\Concerns;

use Illuminate\Http\Request;
use Nawasara\Api\Support\AuthAbuseGuard;
use Symfony\Component\HttpFoundation\Response;

/**
 * Rem per IP sebelum autentikasi, dipakai bersama oleh ketiga middleware
 * autentikasi API. Latar belakangnya ada di AuthAbuseGuard (audit keamanan
 * 15 Oktober 2026, temuan S14).
 *
 * Satu trait, bukan tiga salinan: bila batasnya keliru, perbaikannya cukup di
 * satu tempat dan ketiga jalur ikut benar.
 */
trait GuardsAuthAbuse
{
    /**
     * Jawaban 429 bila IP sudah melewati batas, atau null bila boleh lanjut.
     *
     * Dipanggil di baris PERTAMA handle(), sebelum token dibaca: tujuannya
     * justru menahan permintaan sebelum ada verifikasi JWT, lookup token, atau
     * INSERT log.
     */
    protected function throttleBeforeAuth(Request $request): ?Response
    {
        $retryAfter = $this->abuseGuard()->hit((string) $request->ip());

        if ($retryAfter === null) {
            return null;
        }

        return response()->json([
            'error' => [
                'code' => 'too_many_requests',
                'message' => "Terlalu banyak permintaan dari alamat ini. Coba lagi dalam {$retryAfter} detik.",
            ],
        ], 429, ['Retry-After' => (string) $retryAfter]);
    }

    /**
     * Catat penolakan: hitung ke rem penolakan (khusus 401), lalu putuskan
     * apakah baris log ditulis.
     *
     * Hanya 401 yang dihitung sebagai kegagalan. 403 berarti tokennya SAH
     * (IP/Origin di luar daftar, atau staf belum terdaftar), dan itu bukan
     * pola penebakan token.
     */
    protected function shouldRecordDenial(Request $request, int $status): bool
    {
        $guard = $this->abuseGuard();
        $ip = (string) $request->ip();

        if ($status === 401) {
            $guard->recordFailure($ip);
        }

        return $guard->shouldLogDenial($ip);
    }

    protected function abuseGuard(): AuthAbuseGuard
    {
        return app(AuthAbuseGuard::class);
    }
}
