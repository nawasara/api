<?php

namespace Nawasara\Api\Support;

/**
 * In-memory registry untuk semua scope yang available di sistem.
 *
 * Domain package register scope-nya di service provider mereka, mis.:
 *
 *   if (class_exists(\Nawasara\Api\Facades\Api::class)) {
 *       Api::registerScope('cctv.camera.read', 'List + detail kamera publik');
 *       Api::registerScope('cctv.camera.stream', 'Generate signed stream URL');
 *   }
 *
 * Dipakai UI catalog scope (admin lihat semua scope yang bisa di-assign
 * ke token) + validation saat assign scope (tolak scope yang belum
 * di-register oleh package mana pun).
 */
class ScopeRegistry
{
    /**
     * @var array<string, array{name: string, description: string, group: string}>
     */
    protected array $scopes = [];

    /**
     * Register scope. Idempotent — register ulang dengan key sama overwrite.
     * Group otomatis dari prefix pertama nama scope (sebelum titik pertama).
     */
    public function register(string $name, string $description): void
    {
        $group = str_contains($name, '.')
            ? strstr($name, '.', true)
            : $name;

        $this->scopes[$name] = [
            'name' => $name,
            'description' => $description,
            'group' => $group,
        ];
    }

    public function has(string $name): bool
    {
        return isset($this->scopes[$name]);
    }

    /**
     * @return array<string, array{name: string, description: string, group: string}>
     */
    public function all(): array
    {
        return $this->scopes;
    }

    /**
     * Grouped by package prefix, sorted by scope name. Dipakai UI catalog.
     *
     * @return array<string, array<int, array{name: string, description: string, group: string}>>
     */
    public function grouped(): array
    {
        $grouped = [];

        foreach ($this->scopes as $scope) {
            $grouped[$scope['group']][] = $scope;
        }

        foreach ($grouped as $group => &$scopes) {
            usort($scopes, fn ($a, $b) => $a['name'] <=> $b['name']);
        }
        unset($scopes);

        ksort($grouped);

        return $grouped;
    }
}
