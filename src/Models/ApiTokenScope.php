<?php

namespace Nawasara\Api\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * Assignment scope ke token. Definisi scope itu sendiri (label, deskripsi,
 * owner package) di registry in-code — tabel ini cuma simpan link.
 */
class ApiTokenScope extends Model
{
    protected $table = 'nawasara_api_token_scopes';

    public $timestamps = false;

    protected $fillable = [
        'api_token_id',
        'scope',
        'created_at',
    ];

    protected $casts = [
        'created_at' => 'datetime',
    ];

    public function token(): BelongsTo
    {
        return $this->belongsTo(ApiToken::class, 'api_token_id');
    }
}
