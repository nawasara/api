<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Api\Http\Controllers\MeController;
use Nawasara\Api\Http\Controllers\ScopeController;

/*
|--------------------------------------------------------------------------
| Meta endpoints — owned by nawasara/api itself
|--------------------------------------------------------------------------
| Domain endpoints (CCTV, WiFi, dll) di-define di routes/api.php package
| masing-masing. File ini cuma untuk meta: info token caller + scope list.
*/

Route::get('/me', MeController::class)->name('me');
Route::get('/scopes', ScopeController::class)->name('scopes');
