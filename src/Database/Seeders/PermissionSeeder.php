<?php

namespace Nawasara\Api\Database\Seeders;

use Illuminate\Database\Seeder;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;

class PermissionSeeder extends Seeder
{
    public function run(): void
    {
        $permissions = [
            // Manajemen API token di UI Nawasara internal.
            'api.token.view',
            'api.token.create',
            'api.token.revoke',
        ];

        foreach ($permissions as $permission) {
            Permission::firstOrCreate([
                'name' => $permission,
                'guard_name' => 'web',
            ]);
        }

        // Auto-grant ke role 'developer' kalau ada. Role lain (admin tier)
        // bisa di-assign manual sesuai kebutuhan.
        $role = Role::where('name', 'developer')->first();

        if ($role) {
            $role->givePermissionTo($permissions);
        }
    }
}
