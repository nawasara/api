<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Api\Livewire\AccessLog\Index as AccessLogIndex;
use Nawasara\Api\Livewire\Scope\Index as ScopeIndex;
use Nawasara\Api\Livewire\Token\Index as TokenIndex;
use Spatie\Permission\Middleware\PermissionMiddleware;

Route::middleware(['web', 'auth'])->prefix('nawasara-api')->group(function () {
    Route::get('tokens', TokenIndex::class)
        ->middleware(PermissionMiddleware::using('api.token.view'))
        ->name('nawasara-api.token.index');

    Route::get('scopes', ScopeIndex::class)
        ->middleware(PermissionMiddleware::using('api.token.view'))
        ->name('nawasara-api.scope.index');

    Route::get('access-logs', AccessLogIndex::class)
        ->middleware(PermissionMiddleware::using('api.token.view'))
        ->name('nawasara-api.access-log.index');
});
