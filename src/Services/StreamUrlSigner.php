<?php

namespace Nawasara\Api\Services;

/**
 * HMAC-signed URL untuk endpoint stream proxy.
 *
 * Alur:
 *   1. Endpoint API (mis. /cctv/cameras/{slug}/stream) sign URL pakai
 *      `sign($payload)` → return query string yang ditempel ke URL stream.
 *   2. Client connect ke URL stream tersebut.
 *   3. Nginx `auth_request` panggil endpoint verify-only — controller
 *      verify pakai `verify(...)` → 200/403.
 *   4. Kalau 200, Nginx `proxy_pass` ke service internal.
 *
 * Signing key: APP_KEY Laravel (dari config('app.key')). TTL pendek (5 min
 * default) supaya kebocoran URL terbatas — bukan pengganti token API,
 * cuma supaya stream URL tidak permanen.
 *
 * Payload identifier (mis. slug kamera) di-include di HMAC supaya signed
 * URL untuk slug A tidak bisa dipakai untuk slug B.
 */
class StreamUrlSigner
{
    public function __construct(
        protected string $appKey,
        protected int $ttlSeconds,
        protected string $algorithm = 'sha256',
    ) {}

    /**
     * Sign payload. Return: array{sig: string, exp: int}. Caller tempel ini
     * sebagai query string ke URL stream.
     *
     * @param array<string, string|int> $payload Identifier resource (mis. ['slug' => 'cam-01'])
     */
    public function sign(array $payload, ?int $now = null): array
    {
        $now ??= time();
        $exp = $now + $this->ttlSeconds;

        $sig = $this->compute($payload, $exp);

        return ['sig' => $sig, 'exp' => $exp];
    }

    /**
     * Verify signed URL. Return true kalau sig valid + belum expired.
     *
     * Constant-time compare (`hash_equals`) untuk hindari timing attack.
     *
     * @param array<string, string|int> $payload Identifier resource (sama dengan saat sign)
     */
    public function verify(array $payload, string $sig, int $exp, ?int $now = null): bool
    {
        $now ??= time();

        if ($exp < $now) {
            return false;
        }

        $expected = $this->compute($payload, $exp);

        return hash_equals($expected, $sig);
    }

    /**
     * Hitung HMAC dari payload + exp + app key.
     *
     * Payload di-serialize deterministik: keys di-sort, di-implode dengan
     * separator. Penting supaya order param tidak ubah hash.
     *
     * @param array<string, string|int> $payload
     */
    protected function compute(array $payload, int $exp): string
    {
        ksort($payload);
        $serialized = http_build_query($payload);
        $message = $serialized.'|exp='.$exp;

        return hash_hmac($this->algorithm, $message, $this->appKey);
    }

    public function ttlSeconds(): int
    {
        return $this->ttlSeconds;
    }
}
