<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Nawasara\Api\Models\ApiToken;
use Symfony\Component\HttpFoundation\Response;

/**
 * Cek token punya scope yang dibutuhkan untuk route ini.
 *
 * Usage di route:
 *
 *   Route::get('/cameras', ...)
 *       ->middleware('scope:cctv.camera.read');
 *
 *   Route::get('/admin', ...)
 *       ->middleware('scope:cctv.camera.read,cctv.camera.write'); // butuh KEDUANYA
 *
 * Asumsi: AuthenticateApiToken sudah jalan duluan (token sudah di
 * $request->attributes['api_token']).
 */
class RequireScope
{
    public function handle(Request $request, Closure $next, string ...$requiredScopes): Response
    {
        /** @var ApiToken|null $token */
        $token = $request->attributes->get('api_token');

        if ($token === null) {
            // Middleware mis-konfigurasi — auth.api harus jalan duluan.
            return response()->json([
                'error' => [
                    'code' => 'unauthenticated',
                    'message' => 'Token tidak terauthentikasi sebelum cek scope.',
                ],
            ], 401);
        }

        $tokenScopes = $token->scopeNames();
        $missing = array_diff($requiredScopes, $tokenScopes);

        if (! empty($missing)) {
            return response()->json([
                'error' => [
                    'code' => 'insufficient_scope',
                    'message' => 'Token tidak punya scope yang dibutuhkan.',
                    'required' => array_values($requiredScopes),
                    'missing' => array_values($missing),
                ],
            ], 403);
        }

        return $next($request);
    }
}
