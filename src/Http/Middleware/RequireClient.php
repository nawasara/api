<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Symfony\Component\HttpFoundation\Response;

/**
 * Batasi rute ke client Keycloak tertentu, lewat claim `azp`.
 *
 * Dipasang SESUDAH middleware JWT (`api.staff`, `api.staff.identity`,
 * `api.citizen`):
 *
 *     ->middleware(['api.staff.identity', 'api.client:asn-portal'])
 *
 * Kenapa perlu di samping `allowed_clients` milik verifier: daftar itu
 * berlaku untuk SELURUH jalur, jadi setiap client di dalamnya bisa memanggil
 * setiap endpoint staf. Endpoint akun (keluarkan sesi, hapus passkey, unduh
 * konfigurasi VPN) hanya boleh dipanggil portal akun sendiri, bukan aplikasi
 * lain yang kebetulan juga sah di realm yang sama.
 *
 * ⚠️ HANYA `azp`, tidak ikut `aud`. Realm pegawai memasang audience mapper
 * yang menaruh nama client lain di `aud` token aplikasi lain (13 mapper per
 * Juli 2026). Bila `aud` ikut dihitung, token aplikasi mana pun yang memuat
 * nama portal di `aud`-nya akan lolos. `azp` adalah client yang benar-benar
 * meminta token itu.
 *
 * Tanpa parameter (mis. config client portal belum diisi) → semua DITOLAK.
 * Rute yang lupa dikonfigurasi harus mati, bukan terbuka.
 */
class RequireClient
{
    public function handle(Request $request, Closure $next, string ...$clients): Response
    {
        $clients = array_values(array_filter(array_map('trim', $clients)));

        if ($clients === []) {
            Log::warning('nawasara-api: rute api.client tanpa daftar client, semua permintaan ditolak', [
                'path' => $request->path(),
            ]);

            return $this->deny();
        }

        $claims = $request->attributes->get('staff_claims')
            ?? $request->attributes->get('citizen_claims');

        if (! is_array($claims) || ! self::clientMatches($claims, $clients)) {
            return $this->deny();
        }

        return $next($request);
    }

    /**
     * Pencocokan murni, dipisah supaya dapat diuji tanpa permintaan HTTP.
     *
     * @param  array<string, mixed>  $claims
     * @param  list<string>  $clients
     */
    public static function clientMatches(array $claims, array $clients): bool
    {
        $azp = $claims['azp'] ?? null;

        return is_string($azp) && $azp !== '' && in_array($azp, $clients, true);
    }

    /**
     * 403, bukan 401: tokennya sah, hanya bukan dari aplikasi yang boleh
     * memanggil rute ini. 401 akan membuat aplikasi pemanggil mengira sesinya
     * habis lalu memaksa masuk ulang tanpa henti.
     */
    protected function deny(): Response
    {
        return response()->json([
            'error' => [
                'code' => 'client_not_allowed',
                'message' => 'Aplikasi ini tidak diizinkan memanggil endpoint tersebut.',
            ],
        ], 403);
    }
}
