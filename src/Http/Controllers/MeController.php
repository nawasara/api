<?php

namespace Nawasara\Api\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nawasara\Api\Models\ApiToken;

/**
 * GET /api/v1/me — info token caller.
 *
 * Tidak butuh scope khusus — selalu authenticated (auth.api middleware).
 * Berguna untuk consumer cek "token saya valid, scope apa saja, kapan expired".
 */
class MeController
{
    public function __invoke(Request $request): JsonResponse
    {
        /** @var ApiToken $token */
        $token = $request->attributes->get('api_token');

        return response()->json([
            'data' => [
                'name' => $token->name,
                'token_prefix' => $token->token_prefix,
                'scopes' => $token->scopeNames(),
                'expires_at' => $token->expires_at?->toIso8601String(),
                'created_at' => $token->created_at?->toIso8601String(),
                'last_used_at' => $token->last_used_at?->toIso8601String(),
            ],
        ]);
    }
}
