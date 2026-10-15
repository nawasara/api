<?php

declare(strict_types=1);

namespace Nawasara\Api\Tests;

use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\RateLimiter;
use Illuminate\Cache\Repository;
use Nawasara\Api\Support\AuthAbuseGuard;
use PHPUnit\Framework\TestCase;

/**
 * Rem per IP sebelum autentikasi (audit keamanan 15 Oktober 2026, S14).
 *
 * Memakai RateLimiter sungguhan di atas cache larik, jadi yang diuji adalah
 * kelas yang dipakai middleware, bukan tiruannya.
 */
class AuthAbuseGuardTest extends TestCase
{
    private function guard(int $perMinute = 600, int $failures = 60, int $logs = 10): AuthAbuseGuard
    {
        return new AuthAbuseGuard(
            new RateLimiter(new Repository(new ArrayStore)),
            $perMinute,
            $failures,
            $logs,
        );
    }

    public function test_permintaan_di_bawah_batas_lolos(): void
    {
        $guard = $this->guard(perMinute: 3);

        $this->assertNull($guard->hit('203.0.113.5'));
        $this->assertNull($guard->hit('203.0.113.5'));
        $this->assertNull($guard->hit('203.0.113.5'));
    }

    public function test_melewati_batas_permintaan_dijawab_dengan_detik_tunggu(): void
    {
        $guard = $this->guard(perMinute: 2);

        $guard->hit('203.0.113.5');
        $guard->hit('203.0.113.5');
        $retry = $guard->hit('203.0.113.5');

        $this->assertNotNull($retry);
        $this->assertGreaterThanOrEqual(1, $retry);
        $this->assertLessThanOrEqual(60, $retry);
    }

    /** Satu IP yang membanjiri tidak boleh menghabiskan jatah IP lain. */
    public function test_batas_dihitung_per_ip(): void
    {
        $guard = $this->guard(perMinute: 1);

        $guard->hit('203.0.113.5');
        $this->assertNotNull($guard->hit('203.0.113.5'));
        $this->assertNull($guard->hit('198.51.100.7'));
    }

    /**
     * Penolakan 401 berulang mengunci IP itu, meski jatah permintaannya
     * masih banyak. Inilah rem yang menahan banjir token palsu.
     */
    public function test_penolakan_berulang_mengunci_ip(): void
    {
        $guard = $this->guard(perMinute: 600, failures: 3);

        for ($i = 0; $i < 3; $i++) {
            $this->assertNull($guard->hit('203.0.113.5'));
            $guard->recordFailure('203.0.113.5');
        }

        $this->assertNotNull($guard->hit('203.0.113.5'));
        $this->assertNull($guard->hit('198.51.100.7'));
    }

    public function test_log_penolakan_dibatasi_per_ip(): void
    {
        $guard = $this->guard(logs: 2);

        $this->assertTrue($guard->shouldLogDenial('203.0.113.5'));
        $this->assertTrue($guard->shouldLogDenial('203.0.113.5'));
        $this->assertFalse($guard->shouldLogDenial('203.0.113.5'));

        // IP lain tetap tercatat: penyerang tidak boleh menghapus jejak orang lain.
        $this->assertTrue($guard->shouldLogDenial('198.51.100.7'));
    }

    public function test_nilai_nol_mematikan_rem(): void
    {
        $guard = $this->guard(perMinute: 0, failures: 0, logs: 0);

        for ($i = 0; $i < 50; $i++) {
            $guard->recordFailure('203.0.113.5');
            $this->assertNull($guard->hit('203.0.113.5'));
        }

        $this->assertFalse($guard->shouldLogDenial('203.0.113.5'));
    }
}
