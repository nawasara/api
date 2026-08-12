<?php

namespace Nawasara\Api\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * GET /api/v1/citizen/me — identitas warga yang sedang masuk.
 *
 * Endpoint ini ada lebih dulu daripada seluruh fitur warga, dan memang
 * disengaja: dengan ini pengembang Flutter dapat menguji alur masuk
 * end-to-end SEBELUM nawasara/aspirations selesai. Dua pekerjaan berjalan
 * paralel, bukan berurutan.
 *
 * Tidak menyentuh basis data sama sekali — seluruh isinya berasal dari claim
 * JWT yang sudah diverifikasi middleware. Jadi ia tetap menjawab meski
 * nawasara/citizen belum terpasang.
 */
class CitizenMeController
{
    public function __invoke(Request $request): JsonResponse
    {
        $claims = (array) $request->attributes->get('citizen_claims', []);

        return response()->json([
            'data' => [
                // `sub` adalah penanda warga yang stabil di seluruh Nawasara.
                // Ia tidak berubah meski warga mengganti surel atau menautkan
                // akun Google — karena itu SELALU pakai ini untuk menautkan
                // data, jangan email atau username.
                'sub' => $claims['sub'] ?? null,

                'email' => $claims['email'] ?? null,
                'email_verified' => (bool) ($claims['email_verified'] ?? false),

                // Keycloak mengisi `name` dari firstName + lastName. Realm
                // warga hanya memakai firstName (satu kolom "Nama Lengkap"),
                // jadi keduanya biasanya sama.
                'name' => $claims['name'] ?? $claims['given_name'] ?? null,

                // Cara warga masuk: 'google' bila lewat identity provider,
                // null bila mendaftar mandiri. Berguna bagi aplikasi untuk
                // memutuskan apakah menawarkan penautan akun.
                'identity_provider' => $claims['identity_provider'] ?? null,

                // Kapan token ini kedaluwarsa — aplikasi memakainya untuk
                // menjadwalkan refresh sebelum permintaan berikutnya gagal.
                'expires_at' => isset($claims['exp'])
                    ? date('c', (int) $claims['exp'])
                    : null,
            ],
        ]);
    }
}
