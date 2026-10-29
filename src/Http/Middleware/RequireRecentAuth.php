<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Tuntut login yang masih SEGAR untuk aksi berat, lewat claim `auth_time`.
 *
 *     ->middleware(['api.staff.identity', 'api.recent-auth:300'])
 *
 * Padanan sudo mode di panel, untuk pemanggil yang membawa JWT: menghapus
 * passkey, mengganti autentikator, mengeluarkan perangkat lain, atau
 * mengunduh konfigurasi VPN (yang memuat kunci privat) tidak boleh cukup
 * dengan sesi yang dibuka berjam-jam lalu di perangkat yang mungkin sedang
 * dipinjam orang lain.
 *
 * `auth_time` = kapan pengguna BENAR-BENAR memasukkan kredensial, bukan kapan
 * token diterbitkan. Token yang diperbarui lewat refresh token tetap membawa
 * `auth_time` lama, dan memang itu yang diinginkan: memperpanjang sesi bukan
 * bukti orangnya masih sama.
 *
 * Jawaban 401 `reauth_required` + `max_age`: aplikasi pemanggil mengarahkan
 * pengguna ke Keycloak dengan `max_age=0` (paksa masuk ulang), lalu mengulang
 * aksinya dengan token baru.
 *
 * ⚠️ Token TANPA `auth_time` dianggap BASI, bukan dilewatkan. Keycloak 25+
 * menaruhnya di access token lewat client scope `basic`; client yang tidak
 * memakai scope itu tidak akan pernah lolos di sini — gejalanya "selalu
 * diminta masuk ulang", dan perbaikannya di konfigurasi client, bukan di
 * middleware ini.
 */
class RequireRecentAuth
{
    /** Bawaan bila rute tidak memberi parameter: 5 menit. */
    public const DEFAULT_MAX_AGE = 300;

    public function handle(Request $request, Closure $next, ?string $maxAge = null): Response
    {
        $maxAge = $maxAge !== null && ctype_digit($maxAge) ? (int) $maxAge : self::DEFAULT_MAX_AGE;

        $claims = $request->attributes->get('staff_claims')
            ?? $request->attributes->get('citizen_claims');

        if (! is_array($claims) || ! self::isRecent($claims, $maxAge, time())) {
            return response()->json([
                'error' => [
                    'code' => 'reauth_required',
                    'message' => 'Untuk perubahan ini, silakan masuk ulang terlebih dahulu.',
                    'max_age' => $maxAge,
                ],
            ], 401);
        }

        return $next($request);
    }

    /**
     * Pencocokan murni, dipisah supaya dapat diuji tanpa permintaan HTTP dan
     * tanpa bergantung pada jam.
     *
     * `auth_time` di masa depan (lebih dari selisih jam yang wajar) ditolak:
     * itu bukan login yang segar, melainkan token yang tidak masuk akal.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function isRecent(array $claims, int $maxAge, int $now, int $clockSkew = 30): bool
    {
        $authTime = $claims['auth_time'] ?? null;

        if (! is_int($authTime) && ! (is_string($authTime) && ctype_digit($authTime))) {
            return false;
        }

        $authTime = (int) $authTime;

        if ($authTime > $now + $clockSkew) {
            return false;
        }

        return $now - $authTime <= $maxAge;
    }
}
