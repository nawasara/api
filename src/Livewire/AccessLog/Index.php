<?php

namespace Nawasara\Api\Livewire\AccessLog;

use Livewire\Attributes\Computed;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Api\Models\ApiAccessLog;
use Nawasara\Api\Models\ApiToken;

/**
 * Read-only access log dengan filter:
 *   - token (semua / spesifik token)
 *   - status (semua / 2xx / 4xx / 5xx)
 *   - kind (semua / api / stream_verify)
 *
 * Log retention diatur scheduled command nawasara-api:prune-logs harian.
 */
class Index extends Component
{
    use WithPagination;

    #[Url(except: '')]
    public string $tokenFilter = '';

    #[Url(except: '')]
    public string $statusFilter = '';

    #[Url(except: '')]
    public string $kindFilter = '';

    #[Computed]
    public function logs()
    {
        return ApiAccessLog::query()
            ->with('token:id,name,token_prefix')
            ->when($this->tokenFilter !== '', function ($q) {
                if ($this->tokenFilter === 'unauthenticated') {
                    $q->whereNull('api_token_id');
                } else {
                    $q->where('api_token_id', (int) $this->tokenFilter);
                }
            })
            ->when($this->statusFilter !== '', function ($q) {
                // Filter range status: '2xx' / '4xx' / '5xx'.
                $prefix = (int) substr($this->statusFilter, 0, 1);
                $q->whereBetween('status', [$prefix * 100, $prefix * 100 + 99]);
            })
            ->when($this->kindFilter !== '', fn ($q) => $q->where('kind', $this->kindFilter))
            ->latest('created_at')
            ->paginate(50);
    }

    #[Computed]
    public function stats(): array
    {
        $base = ApiAccessLog::query()
            ->where('created_at', '>=', now()->subDay());

        return [
            'total_24h' => (clone $base)->count(),
            'success_24h' => (clone $base)->whereBetween('status', [200, 299])->count(),
            'failure_24h' => (clone $base)->where('status', '>=', 400)->count(),
            'unique_tokens_24h' => (clone $base)->whereNotNull('api_token_id')->distinct('api_token_id')->count('api_token_id'),
        ];
    }

    /**
     * Daftar token untuk filter dropdown. Include yang sudah revoked supaya
     * log historis tetap bisa di-filter ke token-nya.
     */
    #[Computed]
    public function tokenOptions(): array
    {
        $tokens = ApiToken::query()
            ->orderBy('name')
            ->get(['id', 'name', 'token_prefix', 'revoked_at'])
            ->mapWithKeys(fn ($t) => [
                (string) $t->id => $t->name.' ('.$t->token_prefix.($t->revoked_at ? ' · revoked' : '').')',
            ])
            ->toArray();

        return ['unauthenticated' => 'Tanpa Token (gagal auth)'] + $tokens;
    }

    public function updatedTokenFilter(): void
    {
        $this->resetPage();
    }

    public function updatedStatusFilter(): void
    {
        $this->resetPage();
    }

    public function updatedKindFilter(): void
    {
        $this->resetPage();
    }

    public function render()
    {
        return view('nawasara-api::livewire.pages.access-log.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
