<?php

namespace Nawasara\Api\Services;

/**
 * Verifikasi JWT STAF (ASN) — realm `asn-productions`.
 *
 * Seluruh logikanya diwarisi dari CitizenJwtVerifier; yang berbeda hanya
 * sumber konfigurasinya. Diwarisi, bukan disalin, karena isinya pemeriksaan
 * keamanan — tanda tangan, issuer, kedaluwarsa, rotasi kunci. Dua salinan
 * berarti setiap temuan harus diperbaiki dua kali, dan salinan kedua yang
 * terlupakan adalah lubang yang tidak terlihat sampai dimanfaatkan.
 *
 * Realm warga dan realm staf TIDAK dapat berbagi verifier yang sama pada saat
 * bersamaan: keduanya punya issuer berbeda, kunci penanda tangan berbeda, dan
 * daftar client berbeda. Token warga yang dikirim ke endpoint staf akan gagal
 * pada pemeriksaan issuer — memang itu yang diinginkan.
 *
 * ⚠️ `jwksCacheKey` wajib berbeda dari milik warga. Bila tertukar, kunci realm
 * yang satu akan dipakai memverifikasi token realm lainnya, dan seluruh
 * permintaan ditolak dengan pesan yang menyesatkan ("kunci tidak dikenali")
 * meski konfigurasinya benar.
 */
class StaffJwtVerifier extends CitizenJwtVerifier
{
    protected string $configKey = 'staff';

    protected string $jwksCacheKey = 'nawasara-api:staff-jwks';
}
