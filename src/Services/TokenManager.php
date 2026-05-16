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
     * @param array<int, string> $scopes
     */
    public function create(
        string $name,
        array $scopes = [],
        ?Carbon $expiresAt = null,
        ?int $createdBy = null,
    ): array {
        $plaintext = $this->generatePlaintext();
        $hash = $this->hash($plaintext);

        $token = ApiToken::create([
            'name' => $name,
            'token_hash' => $hash,
            'token_prefix' => substr($plaintext, 0, $this->visiblePrefixLength),
            'expires_at' => $expiresAt,
            'created_by' => $createdBy,
        ]);

        foreach (array_unique($scopes) as $scope) {
            $token->scopes()->create(['scope' => $scope]);
        }

        return ['token' => $token, 'plaintext' => $plaintext];
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
