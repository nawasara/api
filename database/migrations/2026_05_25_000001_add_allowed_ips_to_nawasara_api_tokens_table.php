<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('nawasara_api_tokens', function (Blueprint $table) {
            // Per-token IP allow-list. Null/empty = allow any IP (backward
            // compatible — every existing token keeps working). When
            // populated, each entry is matched against the client IP via
            // Symfony's IpUtils::checkIp, so single IPv4 (1.2.3.4),
            // single IPv6 (2001:db8::1), and CIDR (10.0.0.0/8, 2001:db8::/32)
            // are all supported.
            $table->json('allowed_ips')->nullable()->after('last_used_ip');
        });
    }

    public function down(): void
    {
        Schema::table('nawasara_api_tokens', function (Blueprint $table) {
            $table->dropColumn('allowed_ips');
        });
    }
};
