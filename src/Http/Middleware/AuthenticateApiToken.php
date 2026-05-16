<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Nawasara\Api\Models\ApiAccessLog;
use Nawasara\Api\Services\TokenManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticate request pakai API token.
 *
 * Terima dua header (D = Bearer + X-API-Key):
 *   - Authorization: Bearer nws_xxx
 *   - X-API-Key: nws_xxx
 *
 * Token valid + aktif → simpan model di $request->attributes['api_token']
 * supaya middleware scope + controller bisa akses tanpa lookup ulang.
 *
 * Token invalid → 401 + log gagal-auth (token_id null) ke access log.
 */
class AuthenticateApiToken
{
    public function __construct(
        protected TokenManager $tokens,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $plaintext = $this->extractToken($request);

        if ($plaintext === null) {
            $this->logFailure($request, 401);

            return response()->json([
                'error' => [
                    'code' => 'missing_token',
                    'message' => 'API token tidak ditemukan. Kirim via header Authorization: Bearer <token> atau X-API-Key: <token>.',
                ],
            ], 401);
        }

        $token = $this->tokens->findByPlaintext($plaintext);

        if ($token === null) {
            $this->logFailure($request, 401);

            return response()->json([
                'error' => [
                    'code' => 'invalid_token',
                    'message' => 'Token tidak valid, expired, atau sudah di-revoke.',
                ],
            ], 401);
        }

        // Eager-load scopes biar middleware scope berikutnya hemat query.
        $token->loadMissing('scopes');

        $this->tokens->touchLastUsed($token, $request->ip());

        $request->attributes->set('api_token', $token);

        return $next($request);
    }

    /**
     * Ekstrak plaintext token dari header. Prioritas: Authorization → X-API-Key.
     */
    protected function extractToken(Request $request): ?string
    {
        $auth = $request->header('Authorization');

        if (is_string($auth) && str_starts_with($auth, 'Bearer ')) {
            $candidate = trim(substr($auth, 7));

            if ($candidate !== '') {
                return $candidate;
            }
        }

        $apiKey = $request->header('X-API-Key');

        if (is_string($apiKey) && trim($apiKey) !== '') {
            return trim($apiKey);
        }

        return null;
    }

    protected function logFailure(Request $request, int $status): void
    {
        // Best-effort — jangan crash request hanya karena log gagal.
        try {
            ApiAccessLog::create([
                'api_token_id' => null,
                'method' => $request->method(),
                'path' => substr($request->path(), 0, 512),
                'status' => $status,
                'kind' => ApiAccessLog::KIND_API,
                'ip' => $request->ip(),
                'user_agent' => substr((string) $request->userAgent(), 0, 512),
            ]);
        } catch (\Throwable) {
            // ignore — log table mungkin belum ter-migrate
        }
    }
}
