<?php

namespace Nawasara\Api\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Nawasara\Api\Models\ApiToken;
use Nawasara\Api\Support\ScopeRegistry;

/**
 * GET /api/v1/scopes — daftar scope yang token caller punya, lengkap dengan
 * deskripsi dari registry. Berguna untuk consumer build UI yang adaptif
 * sesuai akses yang dimiliki.
 */
class ScopeController
{
    public function __invoke(Request $request, ScopeRegistry $registry): JsonResponse
    {
        /** @var ApiToken $token */
        $token = $request->attributes->get('api_token');

        $tokenScopes = $token->scopeNames();
        $all = $registry->all();

        $data = [];

        foreach ($tokenScopes as $name) {
            // Kalau scope tidak ter-register (misal package owner unload),
            // tetap tampilkan dengan description placeholder supaya consumer
            // bisa lihat ada scope "ghost" — bukan disembunyikan.
            $data[] = $all[$name] ?? [
                'name' => $name,
                'description' => '(scope tidak ter-register oleh package mana pun)',
                'group' => str_contains($name, '.') ? strstr($name, '.', true) : $name,
            ];
        }

        return response()->json([
            'data' => $data,
            'meta' => ['total' => count($data)],
        ]);
    }
}
