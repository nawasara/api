<?php

declare(strict_types=1);

namespace Nawasara\Api\Tests;

use Illuminate\Http\Request;
use Nawasara\Api\Http\Middleware\RequireClient;
use Nawasara\Api\Http\Middleware\RequireRecentAuth;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Response;

/**
 * Pembatas rute untuk endpoint akun (Akun ASN): `api.client` dan
 * `api.recent-auth`.
 *
 * Keputusan diambil oleh fungsi murni clientMatches() dan isRecent(), jadi
 * keduanya diuji langsung tanpa aplikasi Laravel; jalur yang meneruskan
 * permintaan diuji lewat handle().
 */
class AccountRouteGuardsTest extends TestCase
{
    private const NOW = 1_800_000_000;

    // ---- api.client --------------------------------------------------------

    public function test_client_matches_on_azp(): void
    {
        $this->assertTrue(RequireClient::clientMatches(['azp' => 'asn-portal'], ['asn-portal']));
        $this->assertTrue(RequireClient::clientMatches(['azp' => 'asn-portal'], ['other', 'asn-portal']));
        $this->assertFalse(RequireClient::clientMatches(['azp' => 'nawasara-panel'], ['asn-portal']));
    }

    /**
     * Inti alasan middleware ini ada: realm pegawai memasang audience mapper,
     * jadi token aplikasi LAIN dapat memuat nama portal di `aud`. Itu tidak
     * boleh cukup.
     */
    public function test_client_name_in_aud_is_not_enough(): void
    {
        $claims = ['azp' => 'simashebat', 'aud' => ['account', 'asn-portal']];

        $this->assertFalse(RequireClient::clientMatches($claims, ['asn-portal']));
    }

    public function test_missing_or_empty_azp_never_matches(): void
    {
        $this->assertFalse(RequireClient::clientMatches([], ['asn-portal']));
        $this->assertFalse(RequireClient::clientMatches(['azp' => ''], ['']));
        $this->assertFalse(RequireClient::clientMatches(['azp' => null], ['asn-portal']));
    }

    public function test_client_check_is_case_sensitive(): void
    {
        $this->assertFalse(RequireClient::clientMatches(['azp' => 'ASN-PORTAL'], ['asn-portal']));
    }

    public function test_allowed_client_passes_through_middleware(): void
    {
        $request = $this->requestWithClaims('staff_claims', ['azp' => 'asn-portal', 'sub' => 'abc']);

        $response = (new RequireClient)->handle($request, fn () => new Response('ok'), 'asn-portal');

        $this->assertSame('ok', $response->getContent());
    }

    /** Jalur warga memakai atribut berbeda; middleware harus membaca keduanya. */
    public function test_citizen_claims_are_read_too(): void
    {
        $request = $this->requestWithClaims('citizen_claims', ['azp' => 'citizen-account', 'sub' => 'abc']);

        $response = (new RequireClient)->handle($request, fn () => new Response('ok'), 'citizen-account');

        $this->assertSame('ok', $response->getContent());
    }

    // ---- api.recent-auth ---------------------------------------------------

    public function test_login_within_window_is_recent(): void
    {
        $this->assertTrue(RequireRecentAuth::isRecent(['auth_time' => self::NOW - 60], 300, self::NOW));
        $this->assertTrue(RequireRecentAuth::isRecent(['auth_time' => self::NOW - 300], 300, self::NOW));
    }

    public function test_login_older_than_window_is_stale(): void
    {
        $this->assertFalse(RequireRecentAuth::isRecent(['auth_time' => self::NOW - 301], 300, self::NOW));
        $this->assertFalse(RequireRecentAuth::isRecent(['auth_time' => self::NOW - 86_400], 300, self::NOW));
    }

    /**
     * Token tanpa `auth_time` dianggap basi. Melewatkannya berarti client
     * yang lupa memakai scope `basic` diam-diam lolos dari pemeriksaan ini.
     */
    public function test_missing_auth_time_is_stale(): void
    {
        $this->assertFalse(RequireRecentAuth::isRecent([], 300, self::NOW));
        $this->assertFalse(RequireRecentAuth::isRecent(['auth_time' => null], 300, self::NOW));
        $this->assertFalse(RequireRecentAuth::isRecent(['auth_time' => 'kemarin'], 300, self::NOW));
    }

    public function test_numeric_string_auth_time_is_accepted(): void
    {
        $this->assertTrue(RequireRecentAuth::isRecent(['auth_time' => (string) (self::NOW - 10)], 300, self::NOW));
    }

    public function test_auth_time_far_in_the_future_is_rejected(): void
    {
        $this->assertTrue(RequireRecentAuth::isRecent(['auth_time' => self::NOW + 20], 300, self::NOW));
        $this->assertFalse(RequireRecentAuth::isRecent(['auth_time' => self::NOW + 3_600], 300, self::NOW));
    }

    /**
     * Refresh token memperpanjang sesi tetapi tidak mengubah `auth_time`;
     * yang menentukan tetap kapan kredensial terakhir dimasukkan, bukan `iat`.
     */
    public function test_fresh_iat_does_not_make_an_old_login_recent(): void
    {
        $claims = ['auth_time' => self::NOW - 7_200, 'iat' => self::NOW - 5];

        $this->assertFalse(RequireRecentAuth::isRecent($claims, 300, self::NOW));
    }

    public function test_recent_login_passes_through_middleware(): void
    {
        $request = $this->requestWithClaims('staff_claims', ['sub' => 'abc', 'auth_time' => time() - 30]);

        $response = (new RequireRecentAuth)->handle($request, fn () => new Response('ok'), '300');

        $this->assertSame('ok', $response->getContent());
    }

    /** @param  array<string, mixed>  $claims */
    private function requestWithClaims(string $attribute, array $claims): Request
    {
        $request = Request::create('/api/v1/asn-portal/account', 'GET');
        $request->attributes->set($attribute, $claims);

        return $request;
    }
}
