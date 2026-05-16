<?php

namespace Nawasara\Api\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static void registerScope(string $name, string $description)
 * @method static bool hasScope(string $name)
 * @method static array allScopes()
 *
 * @see \Nawasara\Api\Support\ScopeRegistry
 */
class Api extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'nawasara.api.scope-registry';
    }
}
