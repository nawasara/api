<?php

namespace Nawasara\Api;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Livewire\Livewire;
use Nawasara\Api\Console\Commands\PruneAccessLogsCommand;
use Nawasara\Api\Http\Middleware\AuthenticateApiToken;
use Nawasara\Api\Http\Middleware\AuthenticateCitizenJwt;
use Nawasara\Api\Http\Middleware\LogApiAccess;
use Nawasara\Api\Http\Middleware\RequireScope;
use Nawasara\Api\Services\CitizenJwtVerifier;
use Nawasara\Api\Services\StreamUrlSigner;
use Nawasara\Api\Services\TokenManager;
use Nawasara\Api\Support\ScopeRegistry;
use Symfony\Component\Finder\Finder;

class ApiServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/nawasara-api.php', 'nawasara-api');

        // Scope registry — singleton supaya semua package register ke instance
        // yang sama. Diakses via Facade `Api::registerScope(...)`.
        $this->app->singleton('nawasara.api.scope-registry', fn () => new ScopeRegistry);

        $this->app->singleton(ScopeRegistry::class, fn ($app) => $app->make('nawasara.api.scope-registry'));

        $this->app->singleton(TokenManager::class, fn ($app) => new TokenManager(
            prefix: (string) config('nawasara-api.token.prefix', 'nws'),
            bodyLength: (int) config('nawasara-api.token.body_length', 40),
            visiblePrefixLength: (int) config('nawasara-api.token.visible_prefix_length', 8),
            lastUsedThrottleSeconds: (int) config('nawasara-api.token.last_used_throttle_seconds', 60),
        ));

        $this->app->singleton(StreamUrlSigner::class, fn ($app) => new StreamUrlSigner(
            appKey: (string) config('app.key'),
            ttlSeconds: (int) config('nawasara-api.stream_url.ttl_seconds', 300),
            algorithm: (string) config('nawasara-api.stream_url.algorithm', 'sha256'),
        ));

        // Verifier JWT warga. Singleton supaya cache kunci publik dipakai
        // bersama seluruh permintaan dalam satu proses.
        $this->app->singleton(CitizenJwtVerifier::class, fn () => new CitizenJwtVerifier);
    }

    public function boot(Router $router): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                PruneAccessLogsCommand::class,
            ]);
        }

        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'nawasara-api');

        // Guarded — view:cache crash kalau path component tidak ada.
        if (is_dir(__DIR__.'/../resources/views/components')) {
            Blade::anonymousComponentPath(__DIR__.'/../resources/views/components', 'nawasara-api');
        }

        $this->registerMiddleware($router);
        // Limiter didaftarkan SEBELUM route: throttle:nawasara-citizen di
        // registerMetaRoutes() akan gagal bila namanya belum dikenal.
        $this->registerCitizenRateLimiter();
        $this->registerMetaRoutes();
        $this->registerLivewire();
        $this->registerSchedule();
    }

    /**
     * Auto-discover Livewire components di src/Livewire/. Mengikuti pola
     * package lain (Wifi, Cctv): alias = nawasara-api.<path-kebab>.
     */
    protected function registerLivewire(): void
    {
        $namespace = 'Nawasara\\Api\\Livewire';
        $basePath = __DIR__.'/Livewire';

        if (! is_dir($basePath)) {
            return;
        }

        $finder = new Finder();
        $finder->files()->in($basePath)->name('*.php');

        foreach ($finder as $file) {
            $relativePath = str_replace('/', '\\', $file->getRelativePathname());
            $class = $namespace.'\\'.Str::beforeLast($relativePath, '.php');

            if (class_exists($class)) {
                $alias = 'nawasara-api.'.
                    Str::of($relativePath)
                        ->replace('.php', '')
                        ->replace('\\', '.')
                        ->replace('/', '.')
                        ->explode('.')
                        ->map(fn ($segment) => Str::kebab($segment))
                        ->join('.');

                Livewire::component($alias, $class);
            }
        }
    }

    /**
     * Daftar alias middleware:
     *   - api.auth  → autentikasi token (Bearer/X-API-Key)
     *   - scope     → cek required scope per route
     *   - api.log   → log akses ke api_access_logs
     */
    protected function registerMiddleware(Router $router): void
    {
        $router->aliasMiddleware('api.auth', AuthenticateApiToken::class);
        $router->aliasMiddleware('scope', RequireScope::class);
        $router->aliasMiddleware('api.log', LogApiAccess::class);

        // Jalur WARGA — JWT Keycloak. Alias TERPISAH, bukan cabang di dalam
        // api.auth: kekeliruan pada jalur gabungan akan menjatuhkan Gasta dan
        // integrasi lain sekaligus. Rute lama tidak disentuh sama sekali.
        $router->aliasMiddleware('api.citizen', AuthenticateCitizenJwt::class);
        // Staff JWT alias: some packages expect `api.staff`. For now reuse
        // the citizen verifier implementation so routes resolve. A dedicated
        // staff verifier can be added later if semantics diverge.
        $router->aliasMiddleware('api.staff', AuthenticateCitizenJwt::class);
    }

    /**
     * Mount /me + /scopes endpoint di prefix config (default /api/v1).
     * Domain package mount route mereka sendiri di prefix yang sama lewat
     * helper `nawasaraApi()->routes()` (lihat README package CCTV nanti).
     */
    protected function registerMetaRoutes(): void
    {
        Route::prefix(config('nawasara-api.route.prefix', 'api/v1'))
            ->middleware(['api', 'api.auth', 'api.log'])
            ->name('nawasara-api.')
            ->group(__DIR__.'/../routes/api.php');

        // Endpoint warga — prefix sendiri, middleware sendiri.
        //
        // throttle dikunci pada `sub` warga lewat RateLimiter bernama
        // 'nawasara-citizen' (lihat registerCitizenRateLimiter). Tanpa itu
        // Laravel membatasi per-IP, dan puluhan ribu warga di belakang NAT
        // operator seluler akan saling menghabiskan jatah satu sama lain.
        Route::prefix(config('nawasara-api.route.prefix', 'api/v1').'/citizen')
            ->middleware(['api', 'api.citizen', 'throttle:nawasara-citizen'])
            ->name('nawasara-api.citizen.')
            ->group(__DIR__.'/../routes/citizen.php');
    }

    /**
     * Rate limit per WARGA, bukan per IP.
     *
     * Pembatasan bawaan Laravel memakai IP. Untuk aplikasi ponsel itu keliru:
     * warga di belakang NAT operator seluler berbagi satu IP publik, sehingga
     * beberapa pengguna aktif dapat menghabiskan jatah seluruh pelanggan
     * operator yang sama di wilayah itu.
     *
     * Dikunci pada `sub` — penanda warga yang stabil. Bila `sub` belum ada
     * (permintaan belum terautentikasi), jatuh ke IP sebagai jaring pengaman.
     */
    protected function registerCitizenRateLimiter(): void
    {
        RateLimiter::for('nawasara-citizen', function ($request) {
            $perMinute = (int) config('nawasara-api.citizen.rate_limit_per_minute', 60);
            $key = $request->attributes->get('citizen_sub') ?: $request->ip();

            return Limit::perMinute($perMinute)->by('citizen:'.$key);
        });
    }

    protected function registerSchedule(): void
    {
        $this->app->booted(function () {
            if (! $this->app->runningInConsole()) {
                return;
            }

            $schedule = $this->app->make(Schedule::class);

            // Prune log harian jam 02:00 — sebelum sync titles CCTV (03:00).
            $schedule->command('nawasara-api:prune-logs')
                ->dailyAt('02:00')
                ->withoutOverlapping(30)
                ->runInBackground();
        });
    }
}
