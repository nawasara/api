<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_api_tokens', function (Blueprint $table) {
            $table->id();

            // Label human-readable yang admin lihat di list.
            $table->string('name');

            // SHA-256 dari plaintext token. Plaintext TIDAK pernah disimpan.
            // CHAR(64) — fixed length hex string.
            $table->char('token_hash', 64)->unique();

            // 8 char pertama plaintext untuk identifikasi visual di list
            // (mis. "nws_abc1"). Non-sensitive — boleh ditampilkan di UI.
            $table->string('token_prefix', 16);

            $table->timestamp('last_used_at')->nullable();
            $table->string('last_used_ip', 45)->nullable(); // IPv6 max 45 char

            // Expiry opsional. null = no expiry.
            $table->timestamp('expires_at')->nullable();

            // Revoke = soft-disable. Token gagal auth setelah ini terisi.
            $table->timestamp('revoked_at')->nullable();

            $table->foreignId('created_by')
                ->nullable()
                ->constrained('users')
                ->nullOnDelete();

            $table->timestamps();

            // Filter list yang sering: aktif vs revoked.
            $table->index('revoked_at');
            $table->index('expires_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_api_tokens');
    }
};
