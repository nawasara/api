<?php

namespace Nawasara\Api\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Foundation\Auth\User as AuthUser;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Token API yang dipegang aplikasi consumer.
 *
 * Plaintext token JANGAN PERNAH disimpan di model ini — yang ada cuma
 * hash (cari dengan `findByPlaintext`) dan prefix visual untuk list UI.
 */
class ApiToken extends Model
{
    use HasFactory;

    protected $table = 'nawasara_api_tokens';

    protected $fillable = [
        'name',
        'token_hash',
        'token_prefix',
        'last_used_at',
        'last_used_ip',
        'allowed_ips',
        'allowed_origins',
        'expires_at',
        'revoked_at',
        'created_by',
    ];

    protected $casts = [
        'last_used_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
        'allowed_ips' => 'array',
        'allowed_origins' => 'array',
    ];

    // Hash + plaintext tidak pernah di-serialize. Plaintext memang tidak
    // di-simpan, tapi `token_hash` cukup sensitif kalau pun cuma hash —
    // tidak ada alasan engineer butuh lihat ini di JSON response.
    protected $hidden = [
        'token_hash',
    ];

    public function scopes(): HasMany
    {
        return $this->hasMany(ApiTokenScope::class, 'api_token_id');
    }

    public function accessLogs(): HasMany
    {
        return $this->hasMany(ApiAccessLog::class, 'api_token_id');
    }

    public function creator(): BelongsTo
    {
        // Pakai class user dari config('auth.providers.users.model').
        $userClass = config('auth.providers.users.model', AuthUser::class);

        return $this->belongsTo($userClass, 'created_by');
    }

    /**
     * Aktif = tidak revoked + belum expired (atau no expiry).
     */
    public function scopeActive(Builder $query): Builder
    {
        return $query
            ->whereNull('revoked_at')
            ->where(function (Builder $q) {
                $q->whereNull('expires_at')
                    ->orWhere('expires_at', '>', now());
            });
    }

    public function isRevoked(): bool
    {
        return $this->revoked_at !== null;
    }

    public function isExpired(): bool
    {
        return $this->expires_at !== null && $this->expires_at->isPast();
    }

    public function isActive(): bool
    {
        return ! $this->isRevoked() && ! $this->isExpired();
    }

    /**
     * Apakah token memiliki scope ini? Lookup ke tabel pivot scope.
     */
    public function hasScope(string $scope): bool
    {
        return $this->scopes()->where('scope', $scope)->exists();
    }

    /**
     * Apakah `$ip` cocok dengan daftar IP yang diizinkan untuk token ini?
     *
     * Empty allow-list (null atau []) artinya **opt-out** — token boleh
     * dipakai dari IP mana pun. Ini disengaja agar token existing tetap
     * jalan setelah migrasi; admin baru menambah whitelist saat butuh.
     *
     * Entri yang didukung: IPv4 tunggal (`1.2.3.4`), IPv6 tunggal
     * (`2001:db8::1`), dan CIDR (`10.0.0.0/8`, `2001:db8::/32`). Symfony
     * `IpUtils::checkIp` menangani ketiganya.
     */
    public function isIpAllowed(?string $ip): bool
    {
        $allowed = $this->allowed_ips;

        if (! is_array($allowed) || $allowed === []) {
            return true;
        }

        if (! is_string($ip) || $ip === '') {
            // Token sudah punya allow-list tapi caller tidak mengaku
            // punya IP — tolak. Tidak ada use case yang sah untuk ini.
            return false;
        }

        return IpUtils::checkIp($ip, $allowed);
    }

    /**
     * Apakah `$origin` cocok dengan daftar Origin yang diizinkan?
     *
     * Empty allow-list (null / []) = opt-out, terima dari mana saja —
     * pintu yang sama dengan IP allow-list, menjaga backward compat.
     *
     * Saat allow-list terisi, request TANPA Origin di-tolak: browser
     * yang membuka cross-origin request selalu mengirim Origin, jadi
     * request tanpa header itu pasti bukan browser di domain target —
     * dan token ber-Origin-list memang TIDAK dimaksudkan untuk caller
     * non-browser (curl, server-to-server). Untuk itu, terbitkan token
     * terpisah tanpa allowed_origins.
     *
     * Compare di-normalisasi (lowercase host, strip trailing slash,
     * drop default port) supaya entri user yang manusiawi tetap cocok
     * dengan apa yang browser kirim.
     */
    public function isOriginAllowed(?string $origin): bool
    {
        $allowed = $this->allowed_origins;

        if (! is_array($allowed) || $allowed === []) {
            return true;
        }

        $normalized = self::normalizeOrigin((string) $origin);
        if ($normalized === null) {
            return false;
        }

        foreach ($allowed as $entry) {
            if (self::normalizeOrigin((string) $entry) === $normalized) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize a value menjadi bentuk kanonik `scheme://host[:port]`.
     *
     * Tujuan: entri textarea yang manusiawi (`https://gasta.ponorogo.go.id/`)
     * cocok dengan header yang browser kirim (`https://gasta.ponorogo.go.id`).
     *
     *   - scheme & host di-lowercase
     *   - default port (80 untuk http, 443 untuk https) dihapus
     *   - path / query / fragment di-drop
     *   - trailing slash di-strip
     *
     * Return null untuk input yang bukan absolute URL valid.
     */
    public static function normalizeOrigin(string $value): ?string
    {
        $value = trim($value);
        if ($value === '') {
            return null;
        }

        $parts = parse_url($value);
        if (! is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return null;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $port = $parts['port'] ?? null;

        // Drop default ports (80 / 443) supaya `https://x` == `https://x:443`.
        if (($scheme === 'http' && $port === 80) || ($scheme === 'https' && $port === 443)) {
            $port = null;
        }

        return $scheme.'://'.$host.($port !== null ? ':'.$port : '');
    }

    /**
     * Daftar nama scope sebagai array string (di-cache di properti
     * sementara per-request supaya tidak query berulang).
     */
    public function scopeNames(): array
    {
        return $this->scopes->pluck('scope')->all();
    }
}
