<?php

namespace Nawasara\Api\Support;

use Illuminate\Cache\RateLimiter;

/**
 * Rem per IP yang berjalan SEBELUM autentikasi, untuk ketiga jalur API
 * (`api.auth`, `api.citizen`, `api.staff`).
 *
 * Audit keamanan 15 Oktober 2026, temuan S14. Sebelumnya:
 *
 *   - jalur `nws_` dan `api.staff` tidak punya rate limit sama sekali;
 *   - di jalur warga, `throttle:nawasara-citizen` baru berjalan SETELAH token
 *     diperiksa, sehingga token sampah tidak pernah tertahan olehnya;
 *   - setiap penolakan 401 menulis satu baris `api_access_logs`.
 *
 * Akibatnya satu skrip yang mengirim token palsu terus-menerus dapat
 * membanjiri basis data, karena setiap permintaan berakhir dengan INSERT.
 *
 * Kenapa dipanggil DARI DALAM middleware autentikasi, bukan dipasang sebagai
 * middleware tersendiri di depan grup rute: grup `api.auth` didefinisikan oleh
 * belasan paket (cctv, wifi, job-vacancy, ...). Memasang rem di masing-masing
 * grup berarti satu paket yang lupa menjadi celah. Di dalam middleware
 * autentikasi, setiap rute yang memakai alias itu otomatis ikut terlindungi.
 *
 * Tiga rem, masing-masing dengan alasan sendiri:
 *
 *   per_ip_per_minute       batas kasar semua permintaan dari satu IP.
 *                           Sengaja longgar: ribuan ponsel warga berbagi IP
 *                           operator seluler (CGNAT), dan batas yang ketat di
 *                           sini menghukum warga yang tidak melakukan apa-apa.
 *   failures_per_ip_per_minute
 *                           batas penolakan 401. Inilah rem yang sebenarnya
 *                           menahan banjir token palsu: aplikasi yang sah
 *                           hampir tidak pernah ditolak, jadi angka ini dapat
 *                           jauh lebih kecil daripada batas permintaan.
 *   denial_logs_per_ip_per_minute
 *                           berapa penolakan per IP per menit yang dicatat ke
 *                           `api_access_logs`. Sisanya tidak dicatat: sepuluh
 *                           baris sudah cukup untuk melihat polanya, baris ke
 *                           seribu tidak menambah apa pun selain beban.
 *
 * Nilai 0 mematikan rem yang bersangkutan (untuk log: tidak mencatat sama
 * sekali).
 */
class AuthAbuseGuard
{
    public function __construct(
        protected RateLimiter $limiter,
        protected int $perIpPerMinute = 600,
        protected int $failuresPerIpPerMinute = 60,
        protected int $denialLogsPerIpPerMinute = 10,
    ) {}

    /**
     * Hitung satu permintaan dari IP ini.
     *
     * Mengembalikan jumlah detik yang harus ditunggu bila IP sudah melewati
     * salah satu batas, atau null bila boleh lanjut ke pemeriksaan token.
     */
    public function hit(string $ip): ?int
    {
        // Penolakan diperiksa lebih dulu, dan TANPA menambah hitungan: IP yang
        // sedang dihukum karena token palsu tidak perlu ikut menghabiskan
        // jatah permintaannya sendiri.
        if ($this->failuresPerIpPerMinute > 0
            && $this->limiter->tooManyAttempts($this->failureKey($ip), $this->failuresPerIpPerMinute)) {
            return max(1, $this->limiter->availableIn($this->failureKey($ip)));
        }

        if ($this->perIpPerMinute > 0) {
            $key = $this->requestKey($ip);

            if ($this->limiter->tooManyAttempts($key, $this->perIpPerMinute)) {
                return max(1, $this->limiter->availableIn($key));
            }

            $this->limiter->hit($key, 60);
        }

        return null;
    }

    /** Catat satu penolakan 401 dari IP ini. */
    public function recordFailure(string $ip): void
    {
        if ($this->failuresPerIpPerMinute > 0) {
            $this->limiter->hit($this->failureKey($ip), 60);
        }
    }

    /**
     * Bolehkah penolakan ini ditulis ke `api_access_logs`?
     *
     * Dihitung per IP, bukan global: satu penyerang yang membanjiri tidak
     * boleh menghabiskan jatah catatan sehingga penolakan dari IP lain ikut
     * hilang dari log.
     */
    public function shouldLogDenial(string $ip): bool
    {
        if ($this->denialLogsPerIpPerMinute <= 0) {
            return false;
        }

        $key = $this->denialLogKey($ip);

        if ($this->limiter->tooManyAttempts($key, $this->denialLogsPerIpPerMinute)) {
            return false;
        }

        $this->limiter->hit($key, 60);

        return true;
    }

    protected function requestKey(string $ip): string
    {
        return 'nawasara-api:preauth:req:'.$ip;
    }

    protected function failureKey(string $ip): string
    {
        return 'nawasara-api:preauth:fail:'.$ip;
    }

    protected function denialLogKey(string $ip): string
    {
        return 'nawasara-api:preauth:log:'.$ip;
    }
}
