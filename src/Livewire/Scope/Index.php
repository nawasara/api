<?php

namespace Nawasara\Api\Livewire\Scope;

use Livewire\Attributes\Computed;
use Livewire\Component;
use Nawasara\Api\Models\ApiTokenScope;
use Nawasara\Api\Support\ScopeRegistry;

/**
 * Catalog read-only semua scope yang ter-register di sistem, grouped per
 * package. Admin pakai halaman ini untuk lihat scope mana yang available
 * + berapa token yang sudah pakai tiap scope (audit visibility).
 */
class Index extends Component
{
    #[Computed]
    public function scopeGroups(): array
    {
        $registry = app(ScopeRegistry::class);
        $grouped = $registry->grouped();

        // Hitung berapa token aktif punya tiap scope — untuk audit.
        $counts = ApiTokenScope::query()
            ->selectRaw('scope, COUNT(*) as token_count')
            ->groupBy('scope')
            ->pluck('token_count', 'scope');

        foreach ($grouped as $group => &$scopes) {
            foreach ($scopes as &$scope) {
                $scope['token_count'] = (int) ($counts[$scope['name']] ?? 0);
            }
        }
        unset($scopes, $scope);

        return $grouped;
    }

    #[Computed]
    public function totalScopes(): int
    {
        return count(app(ScopeRegistry::class)->all());
    }

    public function render()
    {
        return view('nawasara-api::livewire.pages.scope.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
