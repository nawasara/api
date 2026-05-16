<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_api_access_logs', function (Blueprint $table) {
            $table->id();

            // Nullable: log gagal-auth (token invalid → tidak ada token id)
            // tetap tercatat untuk forensik attempted abuse.
            $table->foreignId('api_token_id')
                ->nullable()
                ->constrained('nawasara_api_tokens')
                ->nullOnDelete();

            $table->string('method', 8); // GET/POST/HEAD/PUT/PATCH/DELETE

            // Path lengkap, mis. "/api/v1/cctv/cameras". Index supaya bisa
            // filter "siapa hit endpoint X" cepat.
            $table->string('path', 512);

            $table->unsignedSmallInteger('status'); // 200..599

            // Bedain "request endpoint biasa" vs "Nginx auth_request hit
            // untuk stream proxy". 'api' default, 'stream_verify' untuk
            // verify-only endpoint. Tidak pakai enum karena bisa nambah
            // kind baru tanpa migration.
            $table->string('kind', 16)->default('api');

            $table->string('ip', 45)->nullable();
            $table->string('user_agent', 512)->nullable();

            $table->timestamp('created_at')->useCurrent();

            // Prune job filter by created_at + bisa pivot lookup per-token.
            $table->index('created_at');
            $table->index(['api_token_id', 'created_at']);
            $table->index('kind');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_api_access_logs');
    }
};
