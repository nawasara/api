<?php

use Illuminate\Support\Facades\Route;
use Nawasara\Api\Http\Controllers\CitizenMeController;

/*
|--------------------------------------------------------------------------
| Endpoint WARGA — di belakang JWT Keycloak
|--------------------------------------------------------------------------
| TERPISAH dari routes/api.php yang memakai token `nws_`. Dua jalur, dua
| middleware, sengaja tidak digabung: satu titik yang salah di jalur gabungan
| akan menjatuhkan Gasta dan integrasi lain sekaligus.
|
| Paket domain (aspirations, citizen, dst.) mendaftarkan rute warganya sendiri
| dengan alias middleware `api.citizen`, mengikuti pola yang sama.
*/

Route::get('/me', CitizenMeController::class)->name('me');
