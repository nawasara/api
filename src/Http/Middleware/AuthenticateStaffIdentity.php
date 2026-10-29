<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Autentikasi STAF (ASN) dari realm pegawai TANPA menuntut baris `users`.
 *
 * Saudara AuthenticateStaffJwt (`api.staff`), untuk pemanggil yang melayani
 * SELURUH ASN, bukan hanya pengguna panel — pertama kali dipakai Akun ASN
 * (asn.ponorogo.go.id).
 *
 *   api.staff           token sah + baris `users` wajib → Auth::setUser()
 *   api.staff.identity  token sah saja → identitas = `sub`
 *
 * Kenapa tidak cukup `api.staff`: sebagian besar ASN tidak pernah membuka
 * panel Nawasara, jadi tidak punya baris `users`, dan `api.staff` menolak
 * mereka dengan 403 `not_registered`. Alasan penolakan itu tetap benar untuk
 * panel (lihat docblock AuthenticateStaffJwt) — karena itu jalurnya dipisah,
 * bukan `api.staff` yang dilonggarkan.
 *
 * ⚠️ Middleware ini SENGAJA tidak memanggil Auth::setUser(), bahkan bila
 * baris `users`-nya ada. Endpoint di belakangnya melayani "akun saya", bukan
 * pekerjaan panel; menyalakan pengguna akan membawa seluruh permission Spatie
 * ke endpoint yang tidak dirancang untuk memeriksanya. Endpoint mengambil
 * identitas dari atribut `staff_sub`, tidak pernah dari parameter.
 *
 * Pemeriksaan tokennya PERSIS sama dengan `api.staff` (rem per IP, hanya
 * access token, issuer realm pegawai, daftar client), karena diwarisi.
 */
class AuthenticateStaffIdentity extends AuthenticateStaffJwt
{
    public function handle(Request $request, Closure $next): Response
    {
        $claims = $this->authenticate($request);

        if ($claims instanceof Response) {
            return $claims;
        }

        $request->attributes->set('staff_sub', $claims['sub']);
        $request->attributes->set('staff_claims', $claims);

        return $next($request);
    }
}
