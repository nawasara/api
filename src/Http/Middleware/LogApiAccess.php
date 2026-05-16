<?php

namespace Nawasara\Api\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Nawasara\Api\Models\ApiAccessLog;
use Nawasara\Api\Models\ApiToken;
use Symfony\Component\HttpFoundation\Response;

/**
 * Log setiap request API ke nawasara_api_access_logs.
 *
 * Jalan SETELAH AuthenticateApiToken (supaya `api_token` sudah ter-set
 * kalau berhasil auth). Auth failure di-log oleh middleware auth itu
 * sendiri (sebelum throw), bukan di sini.
 */
class LogApiAccess
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        try {
            /** @var ApiToken|null $token */
            $token = $request->attributes->get('api_token');

            ApiAccessLog::create([
                'api_token_id' => $token?->id,
                'method' => $request->method(),
                'path' => substr($request->path(), 0, 512),
                'status' => $response->getStatusCode(),
                'kind' => ApiAccessLog::KIND_API,
                'ip' => $request->ip(),
                'user_agent' => substr((string) $request->userAgent(), 0, 512),
            ]);
        } catch (\Throwable) {
            // Jangan crash response karena log gagal.
        }

        return $response;
    }
}
