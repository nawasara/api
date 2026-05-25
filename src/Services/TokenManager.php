<?php

namespace Nawasara\Api\Services;

use Illuminate\Support\Carbon;
use Illuminate\Support\Str;
use Nawasara\Api\Models\ApiToken;

/**
 * Lifecycle token: generate (plaintext + hash), verify (plaintext → row),
 * revoke. Plaintext token TIDAK pernah disimpan — yang stored cuma hash.
 *
 * Generate plaintext SEKALI di UI generate; setelah itu lost = generate
 * token baru, revoke yang lama.
 */
class TokenManager
{
    public function __construct(
        protected string $prefix,
        protected int $bodyLength,
        protected int $visiblePrefixLength,
        protected int $lastUsedThrottleSeconds,
    ) {}

    /**
     * Generate token baru. Return: array{token: ApiToken, plaintext: string}.
     * Plaintext WAJIB ditampilkan ke user SEKARANG — tidak bisa di-retrieve lagi.
     *
     * `$allowedIps` & `$allowedOrigins` opsional. Empty array = no allow-list
     * = token boleh dipakai dari IP / Origin mana pun. Setiap entri harus
     * sudah valid; caller (UI) bertugas validasi sebelum dilempar ke sini.
     * `allowed_origins` di-normalize di sini supaya bentuk simpan kanonik.
     *
     * @param array<int, string> $scopes
     * @param array<int, string> $allowedIps
     * @param array<int, string> $allowedOrigins
     */
    public function create(
        string $name,
        array $scopes = [],
        ?Carbon $expiresAt = null,
        ?int $createdBy = null,
        array $allowedIps = [],
        array $allowedOrigins = [],
    ): array {
        $plaintext = $this->generatePlaintext();
        $hash = $this->hash($plaintext);

        $token = ApiToken::create([
            'name' => $name,
            'token_hash' => $hash,
            'token_prefix' => substr($plaintext, 0, $this->visiblePrefixLength),
            'allowed_ips' => $allowedIps !== [] ? array_values(array_unique($allowedIps)) : null,
            'allowed_origins' => self::normalizeOriginList($allowedOrigins),
            'expires_at' => $expiresAt,
            'created_by' => $createdBy,
        ]);

        foreach (array_unique($scopes) as $scope) {
            $token->scopes()->create(['scope' => $scope]);
        }

        return ['token' => $token, 'plaintext' => $plaintext];
    }

    /**
     * Replace the IP allow-list for an existing token. Pass an empty array
     * to remove the allow-list (token reverts to "allow any IP").
     *
     * @param array<int, string> $allowedIps
     */
    public function updateAllowedIps(ApiToken $token, array $allowedIps): void
    {
        $token->forceFill([
            'allowed_ips' => $allowedIps !== [] ? array_values(array_unique($allowedIps)) : null,
        ])->save();
    }

    /**
     * Replace the Origin allow-list. Empty array removes the restriction.
     * Entries di-normalize ke `scheme://host[:port]` agar bentuk simpan
     * stabil — itu juga yang dipakai middleware saat compare.
     *
     * @param array<int, string> $allowedOrigins
     */
    public function updateAllowedOrigins(ApiToken $token, array $allowedOrigins): void
    {
        $token->forceFill([
            'allowed_origins' => self::normalizeOriginList($allowedOrigins),
        ])->save();
    }

    /**
     * Normalize a raw origin list to its canonical, deduplicated form.
     * Entri yang gagal di-parse (return null dari ApiToken::normalizeOrigin)
     * di-drop, bukan di-pertahankan apa adanya — kalau caller berhasil
     * lolos validasi UI tapi entri tetap gagal parse di sini, simpan apa
     * pun yang gagal-parse cuma akan membuat compare middleware diam-diam
     * tidak cocok. Better drop early.
     *
     * Return null saat list akhirnya kosong, supaya kolom DB konsisten
     * dengan "no allow-list" alih-alih `[]`.
     *
     * @param array<int, string> $list
     * @return array<int, string>|null
     */
    protected static function normalizeOriginList(array $list): ?array
    {
        $normalised = [];

        foreach ($list as $entry) {
            $canon = ApiToken::normalizeOrigin((string) $entry);
            if ($canon !== null) {
                $normalised[$canon] = true;
            }
        }

        return $normalised === [] ? null : array_keys($normalised);
    }

    /**
     * Cari token by plaintext. Return null kalau tidak match atau tidak aktif.
     * Caller HARUS tetap cek scope per-route via middleware.
     */
    public function findByPlaintext(string $plaintext): ?ApiToken
    {
        if (! $this->looksLikeToken($plaintext)) {
            return null;
        }

        $hash = $this->hash($plaintext);

        $token = ApiToken::query()
            ->with('scopes')
            ->where('token_hash', $hash)
            ->first();

        if ($token === null || ! $token->isActive()) {
            return null;
        }

        return $token;
    }

    /**
     * Touch last_used_at + last_used_ip dengan throttle — supaya burst request
     * tidak spam DB. Pakai cache key per-token + interval throttle.
     */
    public function touchLastUsed(ApiToken $token, ?string $ip): void
    {
        $cacheKey = "nawasara-api:token:{$token->id}:touched";

        if (cache()->has($cacheKey)) {
            return;
        }

        $token->forceFill([
            'last_used_at' => now(),
            'last_used_ip' => $ip,
        ])->save();

        cache()->put($cacheKey, true, $this->lastUsedThrottleSeconds);
    }

    public function revoke(ApiToken $token): void
    {
        if ($token->revoked_at !== null) {
            return;
        }

        $token->forceFill(['revoked_at' => now()])->save();
    }

    /**
     * Hash plaintext jadi 64-char hex. SHA-256 cukup; jangan pakai bcrypt
     * di sini karena kita perlu deterministic hash untuk lookup, dan
     * plaintext sudah punya entropy tinggi (240 bit) sehingga GPU brute-force
     * sample-by-sample tidak feasible.
     */
    public function hash(string $plaintext): string
    {
        return hash('sha256', $plaintext);
    }

    /**
     * Bentuk: <prefix>_<random N chars>. Random pakai Str::random (CSPRNG).
     */
    public function generatePlaintext(): string
    {
        return $this->prefix.'_'.Str::random($this->bodyLength);
    }

    protected function looksLikeToken(string $candidate): bool
    {
        $expectedLength = strlen($this->prefix) + 1 + $this->bodyLength;

        if (strlen($candidate) !== $expectedLength) {
            return false;
        }

        return str_starts_with($candidate, $this->prefix.'_');
    }
}
