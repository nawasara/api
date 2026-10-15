<?php

declare(strict_types=1);

namespace Nawasara\Api\Tests;

use Nawasara\Api\Services\CitizenJwtVerifier;
use PHPUnit\Framework\TestCase;

/**
 * Pemeriksaan klaim JWT yang tidak bergantung pada tanda tangan.
 *
 * Audit keamanan 15 Oktober 2026: R1 (ID token diterima sebagai access token)
 * dan S12 (pencocokan client).
 */
class JwtClaimChecksTest extends TestCase
{
    public function test_hanya_access_token_yang_diterima(): void
    {
        $this->assertTrue(CitizenJwtVerifier::isAccessToken(['typ' => 'Bearer']));

        $this->assertFalse(CitizenJwtVerifier::isAccessToken(['typ' => 'ID']));
        $this->assertFalse(CitizenJwtVerifier::isAccessToken(['typ' => 'Refresh']));
        $this->assertFalse(CitizenJwtVerifier::isAccessToken(['typ' => 'bearer']));
        $this->assertFalse(CitizenJwtVerifier::isAccessToken([]));
    }

    /** Keycloak menaruh nama client di `azp`, dan sering hanya "account" di `aud`. */
    public function test_client_dicocokkan_lewat_azp(): void
    {
        $claims = ['azp' => 'pramana-mobile', 'aud' => 'account'];

        $this->assertTrue(CitizenJwtVerifier::clientAllowed($claims, ['pramana-mobile']));
        $this->assertFalse(CitizenJwtVerifier::clientAllowed($claims, ['panel-lain']));
    }

    public function test_client_dicocokkan_lewat_aud_larik(): void
    {
        $claims = ['azp' => 'gateway', 'aud' => ['account', 'nawasara-panel']];

        $this->assertTrue(CitizenJwtVerifier::clientAllowed($claims, ['nawasara-panel']));
        $this->assertFalse(CitizenJwtVerifier::clientAllowed($claims, ['lain']));
    }
}
