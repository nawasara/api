<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_api_tokens', function (Blueprint $table) {
            // Per-token Origin allow-list for browser/SPA consumers
            // (Gasta and friends). Null/empty = no restriction (backward
            // compatible). When populated, the middleware compares the
            // request's Origin header against this list — request without
            // an Origin header is rejected, since well-behaved browsers
            // always set one on cross-origin requests; absence implies a
            // non-browser caller (curl, server-to-server), which a token
            // bound to specific origins is not meant for.
            //
            // Entries are stored normalised: lowercase scheme+host, no
            // trailing slash, no path/query (just scheme://host[:port]).
            $table->json('allowed_origins')->nullable()->after('allowed_ips');
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_api_tokens', function (Blueprint $table) {
            $table->dropColumn('allowed_origins');
        });
    }
};
