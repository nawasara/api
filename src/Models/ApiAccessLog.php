<?php

namespace Nawasara\Api\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Log akses API. Tabel volume tinggi — bukan activity-log Spatie supaya
 * bisa pakai schema simpel + index khusus + retention prune.
 */
class ApiAccessLog extends Model
{
    protected $table = 'nawasara_api_access_logs';

    public const UPDATED_AT = null;

    public const KIND_API = 'api';
    public const KIND_STREAM_VERIFY = 'stream_verify';

    /**
     * Token valid but the caller's IP is not in its allow-list. Separate
     * kind so admin can filter "show me every IP-blocked attempt" without
     * grepping through normal 401/403s.
     */
    public const KIND_IP_DENIED = 'ip_denied';

    protected $fillable = [
        'api_token_id',
        'method',
        'path',
        'status',
        'kind',
        'ip',
        'user_agent',
        'created_at',
    ];

    protected $casts = [
        'status' => 'integer',
        'created_at' => 'datetime',
    ];

    public function token(): BelongsTo
    {
        return $this->belongsTo(ApiToken::class, 'api_token_id');
    }
}
