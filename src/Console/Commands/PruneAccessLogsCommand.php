<?php

namespace Nawasara\Api\Console\Commands;

use Illuminate\Console\Command;
use Nawasara\Api\Models\ApiAccessLog;

/**
 * Prune access log row lebih tua dari retention. Dijadwalkan harian.
 *
 *   php artisan nawasara-api:prune-logs
 */
class PruneAccessLogsCommand extends Command
{
    protected $signature = 'nawasara-api:prune-logs
                            {--days= : Override retention days dari config}';

    protected $description = 'Hapus row api_access_logs lebih lama dari retention period.';

    public function handle(): int
    {
        $days = (int) ($this->option('days') ?: config('nawasara-api.log_retention_days', 90));

        if ($days < 1) {
            $this->error('Retention days minimal 1.');

            return self::INVALID;
        }

        $cutoff = now()->subDays($days);

        $deleted = ApiAccessLog::query()
            ->where('created_at', '<', $cutoff)
            ->delete();

        $this->info("Pruned {$deleted} access log entries older than {$days} days (sebelum {$cutoff->toDateTimeString()}).");

        return self::SUCCESS;
    }
}
