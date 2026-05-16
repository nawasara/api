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
