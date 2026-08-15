<?php

namespace Nawasara\Api\Services;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * Verifikasi JWT warga (realm Keycloak) SECARA LOKAL.
 *
 * Prinsipnya sama dengan yang sudah dianut nawasara/keycloak: realm tidak
 * berada di jalur request. Kunci publik diambil sekali lalu di-cache, sehingga
 * Keycloak yang lambat atau sedang restart TIDAK ikut menjatuhkan API — pada
 * skala puluhan ribu warga, memanggil Keycloak tiap permintaan bukan pilihan.
 *
 * Berdampingan dengan AuthenticateApiToken, bukan menggantikannya. Token `nws_`
 * milik sistem tepercaya (Gasta, integrasi antar-sistem) tetap lewat jalur
 * lamanya tanpa perubahan.
 */
class CitizenJwtVerifier
{
    /**
     * Toleransi selisih jam antara server ini dan Keycloak, dalam detik.
     * Tanpa ini, beda beberapa detik saja membuat token yang baru diterbitkan
     * ditolak sebagai "belum berlaku" (nbf/iat) — gejalanya acak dan sulit
     * dilacak karena hanya muncul di sebagian permintaan.
     */
    protected const LEEWAY = 30;

    /**
     * Cabang config yang dibaca kelas ini.
     *
     * Dijadikan properti, bukan string keras, supaya realm lain (staf ASN)
     * dapat memakai ULANG seluruh logika verifikasi di bawah hanya dengan
     * menimpa dua properti ini. Menyalin kelasnya akan berarti dua salinan
     * pemeriksaan keamanan yang harus diperbaiki dua kali setiap ada temuan.
     */
    protected string $configKey = 'citizen';

    /** Kunci cache JWKS — WAJIB berbeda per realm, kuncinya tidak sama. */
    protected string $jwksCacheKey = 'nawasara-api:citizen-jwks';

    /**
     * Verifikasi token; kembalikan claim bila sah, null bila tidak.
     *
     * Sengaja TIDAK melempar exception ke pemanggil: middleware perlu menjawab
     * 401 dengan bentuk yang seragam, bukan meneruskan pesan galat pustaka
     * yang bisa membocorkan detail konfigurasi ke pemanggil.
     */
    public function verify(string $token): ?array
    {
        $issuer = $this->issuer();

        if ($issuer === '') {
            Log::warning('nawasara-api: citizen JWT issuer belum dikonfigurasi.');

            return null;
        }

        $keys = $this->publicKeys();

        if ($keys === []) {
            Log::warning('nawasara-api: JWKS realm warga kosong / gagal diambil.');

            return null;
        }

        [$claims, $unknownKey] = $this->decode($token, $keys);

        // Kunci tidak dikenali? Kemungkinan Keycloak baru merotasi kunci dan
        // cache kita memuat set lama. Segarkan SEKALI lalu coba lagi.
        //
        // Tanpa ini, rotasi kunci membuat SELURUH warga ditolak sampai TTL
        // cache habis — bisa sejam penuh, dan gejalanya tampak seperti
        // kerusakan besar padahal cukup satu pembacaan ulang.
        //
        // HANYA untuk kegagalan pencocokan kunci. Token kedaluwarsa atau
        // tanda tangan palsu tidak akan membaik dengan kunci baru, dan
        // memanggil ulang JWKS untuk itu membuka jalan penyalahgunaan:
        // pemanggil bisa memaksa kita membanjiri Keycloak dengan token sampah.
        if ($claims === null && $unknownKey) {
            $this->forgetKeys();
            $keys = $this->publicKeys();

            if ($keys !== []) {
                [$claims] = $this->decode($token, $keys);
            }
        }

        if ($claims === null) {
            return null;
        }

        // Tanda tangan sah TIDAK cukup. Token yang diterbitkan realm lain di
        // server Keycloak yang sama juga bertanda tangan sah — issuer harus
        // dicocokkan, kalau tidak pegawai bisa memakai tokennya untuk
        // menembus endpoint warga.
        if (($claims['iss'] ?? null) !== $issuer) {
            Log::debug('nawasara-api: issuer JWT tidak cocok', [
                'expected' => $issuer,
                'got' => $claims['iss'] ?? null,
            ]);

            return null;
        }

        if (! $this->audienceAllowed($claims)) {
            Log::debug('nawasara-api: audience JWT tidak diterima', [
                'aud' => $claims['aud'] ?? null,
                'azp' => $claims['azp'] ?? null,
            ]);

            return null;
        }

        // `sub` adalah satu-satunya penanda warga yang stabil. Tanpa itu token
        // tidak berguna bagi kita, seberapa pun sahnya.
        if (! isset($claims['sub']) || $claims['sub'] === '') {
            return null;
        }

        return $claims;
    }

    /**
     * Decode + verifikasi tanda tangan.
     *
     * @return array{0: ?array, 1: bool} [claims, kunciTidakDikenal]
     *
     * Nilai kedua membedakan "kunci tidak ada di set kita" — yang bisa
     * diperbaiki dengan menyegarkan JWKS — dari kegagalan lain seperti token
     * kedaluwarsa atau tanda tangan palsu, yang tidak akan membaik.
     */
    protected function decode(string $token, array $keys): array
    {
        try {
            JWT::$leeway = self::LEEWAY;

            // decode() memverifikasi tanda tangan, exp, nbf, dan iat sekaligus.
            return [(array) JWT::decode($token, $keys), false];
        } catch (\UnexpectedValueException $e) {
            // php-jwt melempar UnexpectedValueException untuk "kid tidak
            // ditemukan" MAUPUN beberapa galat lain, jadi pesannya diperiksa.
            // Rapuh, tetapi alternatifnya menyegarkan JWKS pada SETIAP token
            // gagal — dan itu membuat kita bisa dibanjiri dari luar.
            $unknownKey = str_contains($e->getMessage(), '"kid"')
                || str_contains($e->getMessage(), 'unable to lookup correct key');

            Log::debug('nawasara-api: verifikasi JWT warga gagal', [
                'reason' => $e->getMessage(),
                'unknown_key' => $unknownKey,
            ]);

            return [null, $unknownKey];
        } catch (\Throwable $e) {
            // Kedaluwarsa, belum berlaku, tanda tangan rusak. Level debug
            // saja: pada endpoint publik token tidak sah adalah kejadian
            // biasa, dan menjadikannya warning akan menenggelamkan log.
            Log::debug('nawasara-api: verifikasi JWT warga gagal', ['reason' => $e->getMessage()]);

            return [null, false];
        }
    }

    /**
     * Audience yang diterima.
     *
     * Keycloak sering menaruh nama client di `azp` dan `account` di `aud`,
     * sehingga memeriksa `aud` saja menolak token yang sebenarnya sah. Kedua
     * claim diperiksa. Bila daftar client di config kosong, pemeriksaan ini
     * dilewati — issuer sudah menyempitkan asal token ke satu realm.
     */
    protected function audienceAllowed(array $claims): bool
    {
        $allowed = array_filter((array) config("nawasara-api.{$this->configKey}.allowed_clients", []));

        if ($allowed === []) {
            return true;
        }

        $aud = (array) ($claims['aud'] ?? []);
        $azp = $claims['azp'] ?? null;

        if ($azp !== null && in_array($azp, $allowed, true)) {
            return true;
        }

        return array_intersect($aud, $allowed) !== [];
    }

    /** Issuer yang diharapkan — harus persis sama dengan claim `iss`. */
    public function issuer(): string
    {
        $base = rtrim((string) config("nawasara-api.{$this->configKey}.base_url", ''), '/');
        $realm = trim((string) config("nawasara-api.{$this->configKey}.realm", ''), '/');

        if ($base === '' || $realm === '') {
            return '';
        }

        // rtrim/trim di atas bukan kehati-hatian berlebihan: nilai ini datang
        // dari .env yang diisi manusia, dan Keycloak >= 25 menolak URL yang
        // tidak ternormalisasi. Pola yang sama sudah ada di KeycloakClient.
        return "{$base}/realms/{$realm}";
    }

    /**
     * Kunci publik dari JWKS.
     *
     * ⚠️ Yang di-cache adalah JSON MENTAH, bukan hasil JWK::parseKeySet().
     * Hasil parse berisi objek OpenSSLAsymmetricKey yang TIDAK dapat
     * diserialisasi — cache driver database/redis akan melempar
     * "Serialization of 'OpenSSLAsymmetricKey' is not allowed", dan
     * verifikasi gagal total. Ini terjadi di produksi, bukan dugaan.
     *
     * Parsing ulang tiap permintaan murah; yang mahal adalah panggilan HTTP
     * ke Keycloak, dan itu tetap terhindar.
     *
     * TTL panjang karena kunci Keycloak jarang berganti. Saat rotasi terjadi,
     * kegagalan pencocokan kunci memicu satu kali segar-ulang — lihat verify().
     */
    protected function publicKeys(): array
    {
        $ttl = (int) config("nawasara-api.{$this->configKey}.jwks_ttl", 3600);

        $jwks = Cache::remember(
            $this->jwksCacheKey,
            $ttl,
            fn () => $this->fetchJwks(),
        );

        if ($jwks === []) {
            return [];
        }

        try {
            return JWK::parseKeySet($jwks, 'RS256');
        } catch (\Throwable $e) {
            Log::warning('nawasara-api: JWKS realm warga gagal di-parse', [
                'reason' => $e->getMessage(),
            ]);

            return [];
        }
    }

    /**
     * Ambil JWKS mentah dari Keycloak. Dikembalikan sebagai array biasa supaya
     * aman diserialisasi cache — lihat catatan di publicKeys().
     *
     * ⚠️ Menyaring `use: enc`. Realm Keycloak menyajikan DUA kunci — satu
     * untuk tanda tangan (`sig`, RS256) dan satu untuk enkripsi (`enc`,
     * RSA-OAEP). Meneruskan kunci enkripsi ke JWK::parseKeySet() membuatnya
     * melempar karena algoritmanya bukan algoritma tanda tangan — dan SELURUH
     * set gagal, termasuk kunci yang sebenarnya benar.
     */
    protected function fetchJwks(): array
    {
        $url = $this->issuer().'/protocol/openid-connect/certs';

        try {
            $response = Http::timeout(10)->acceptJson()->get($url);

            if ($response->failed()) {
                return [];
            }

            $jwks = (array) $response->json();

            $jwks['keys'] = array_values(array_filter(
                $jwks['keys'] ?? [],
                fn ($k) => ($k['use'] ?? 'sig') === 'sig'
            ));

            return $jwks['keys'] === [] ? [] : $jwks;
        } catch (\Throwable $e) {
            Log::warning('nawasara-api: gagal mengambil JWKS realm warga', [
                'url' => $url,
                'reason' => $e->getMessage(),
            ]);

            return [];
        }
    }

    /**
     * Buang cache JWKS. Dipanggil saat Keycloak merotasi kunci dan token
     * mulai ditolak padahal seharusnya sah.
     */
    public function forgetKeys(): void
    {
        Cache::forget($this->jwksCacheKey);
    }
}
