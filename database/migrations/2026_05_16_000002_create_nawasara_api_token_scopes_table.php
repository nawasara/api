<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('nawasara_api_token_scopes', function (Blueprint $table) {
            $table->id();

            $table->foreignId('api_token_id')
                ->constrained('nawasara_api_tokens')
                ->cascadeOnDelete();

            // Nama scope, mis. "cctv.camera.read". Definisi scope itu sendiri
            // ada di registry in-code (Api::registerScope), tabel ini cuma
            // simpan assignment token → scope.
            $table->string('scope');

            $table->timestamp('created_at')->useCurrent();

            // Lookup utama saat middleware cek scope.
            $table->unique(['api_token_id', 'scope']);
            $table->index('scope');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('nawasara_api_token_scopes');
    }
};
