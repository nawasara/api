<?php

namespace Nawasara\Api\Livewire\Token;

use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;
use Livewire\Attributes\Computed;
use Livewire\Attributes\Url;
use Livewire\Component;
use Livewire\WithPagination;
use Nawasara\Api\Models\ApiToken;
use Nawasara\Api\Services\TokenManager;
use Nawasara\Api\Support\ScopeRegistry;
use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Manajemen API token publik. Listing + generate baru + revoke.
 *
 * Plaintext token ditampilkan SEKALI di modal setelah generate — setelah
 * modal ditutup, token tidak bisa di-recover (cuma hash di DB).
 */
class Index extends Component
{
    use WithPagination;

    #[Url(except: '')]
    public string $search = '';

    /** Filter status: '' = semua, 'active', 'revoked', 'expired'. */
    #[Url(except: '')]
    public string $statusFilter = '';

    // -- Generate modal state --------------------------------------------------
    public bool $showCreate = false;

    public string $name = '';

    /** Daftar scope yang di-tick admin (array of scope names). */
    public array $selectedScopes = [];

    /** Tanggal expiry (Y-m-d). Kosong = tidak expired. */
    public string $expiresAt = '';

    /**
     * Daftar IP/CIDR yang diizinkan, sebagai teks bebas (satu per baris
     * atau dipisah koma). Kosong = tidak ada whitelist = boleh dari IP
     * mana pun (opt-in feature). Parsing & validasi di parseAllowedIps().
     */
    public string $allowedIpsInput = '';

    /**
     * Daftar Origin yang diizinkan (browser/SPA). Sama parsing-nya dengan
     * IP list — satu per baris atau dipisah koma. Kosong = boleh dari
     * Origin mana pun. Validasi memastikan tiap entri scheme://host valid.
     */
    public string $allowedOriginsInput = '';

    // -- Plaintext modal — ditampilkan SEKALI setelah generate -----------------
    public bool $showPlaintext = false;
    public string $plaintextToken = '';
    public string $plaintextTokenName = '';

    // -- Edit scope modal ------------------------------------------------------
    public bool $showEditScopes = false;
    public ?int $editingTokenId = null;
    public array $editScopes = [];

    // -- Edit IP allow-list modal ----------------------------------------------
    public bool $showEditIps = false;
    public ?int $editingIpsTokenId = null;
    public string $editIpsInput = '';

    // -- Edit Origin allow-list modal ------------------------------------------
    public bool $showEditOrigins = false;
    public ?int $editingOriginsTokenId = null;
    public string $editOriginsInput = '';

    protected function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'selectedScopes' => ['array'],
            'selectedScopes.*' => ['string'],
            'expiresAt' => ['nullable', 'date', 'after:today'],
            'allowedIpsInput' => ['nullable', 'string', $this->ipListRule()],
            'allowedOriginsInput' => ['nullable', 'string', $this->originListRule()],
        ];
    }

    /**
     * Closure rule untuk textarea Origin allow-list. Setiap entri harus
     * parse jadi scheme://host[:port] valid via ApiToken::normalizeOrigin.
     * Empty string lolos (= tidak ada whitelist).
     */
    protected function originListRule(): \Closure
    {
        return function (string $attribute, mixed $value, \Closure $fail): void {
            foreach ($this->parseIpInput((string) $value) as $entry) {
                if (ApiToken::normalizeOrigin($entry) === null) {
                    $fail("Entri \"{$entry}\" bukan URL Origin yang valid (contoh: https://gasta.ponorogo.go.id).");
                    return;
                }
            }
        };
    }

    /**
     * Closure rule untuk textarea IP allow-list. Setiap entri (satu per
     * baris atau dipisah koma) diuji apakah parseable sebagai IPv4, IPv6,
     * atau CIDR. Empty string lolos (= tidak ada whitelist).
     */
    protected function ipListRule(): \Closure
    {
        return function (string $attribute, mixed $value, \Closure $fail): void {
            foreach ($this->parseIpInput((string) $value) as $entry) {
                if (! $this->isValidIpOrCidr($entry)) {
                    $fail("Entri \"{$entry}\" bukan IP atau CIDR yang valid.");
                    return;
                }
            }
        };
    }

    /**
     * Pecah teks bebas (textarea) jadi array entri IP/CIDR. Pisahkan per
     * baris atau koma, trim whitespace, drop empty.
     *
     * @return array<int, string>
     */
    protected function parseIpInput(string $input): array
    {
        if (trim($input) === '') {
            return [];
        }

        $parts = preg_split('/[\s,]+/', $input) ?: [];

        return array_values(array_filter(array_map('trim', $parts), fn ($v) => $v !== ''));
    }

    /**
     * Cek satu entri benar IPv4/IPv6/CIDR. Strategi: probe dengan
     * IpUtils::checkIp pakai IP dummy. Kalau parse gagal, IpUtils throw
     * atau return false untuk syntax invalid; kalau syntax valid tapi
     * tidak match dummy, itu OK — yang kita uji parser-nya, bukan match.
     */
    protected function isValidIpOrCidr(string $entry): bool
    {
        // CIDR shape — has '/'
        if (str_contains($entry, '/')) {
            [$ip, $mask] = explode('/', $entry, 2);

            if (! filter_var($ip, FILTER_VALIDATE_IP)) {
                return false;
            }

            if (! ctype_digit($mask)) {
                return false;
            }

            $mask = (int) $mask;
            $maxMask = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) ? 32 : 128;

            return $mask >= 0 && $mask <= $maxMask;
        }

        return (bool) filter_var($entry, FILTER_VALIDATE_IP);
    }

    #[Computed]
    public function tokens()
    {
        $query = ApiToken::query()
            ->with(['scopes', 'creator'])
            ->when($this->search, fn ($q) => $q->where(function ($q) {
                $q->where('name', 'like', "%{$this->search}%")
                    ->orWhere('token_prefix', 'like', "%{$this->search}%");
            }))
            ->latest('created_at');

        // Status filter — compose where berdasarkan revoked/expired/active.
        if ($this->statusFilter === 'active') {
            $query->active();
        } elseif ($this->statusFilter === 'revoked') {
            $query->whereNotNull('revoked_at');
        } elseif ($this->statusFilter === 'expired') {
            $query->whereNull('revoked_at')
                ->whereNotNull('expires_at')
                ->where('expires_at', '<=', now());
        }

        return $query->paginate(20);
    }

    #[Computed]
    public function stats(): array
    {
        $total = ApiToken::count();
        $active = ApiToken::active()->count();
        $revoked = ApiToken::whereNotNull('revoked_at')->count();
        $expired = ApiToken::whereNull('revoked_at')
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', now())
            ->count();

        return compact('total', 'active', 'revoked', 'expired');
    }

    /**
     * Daftar scope yang ter-register, grouped per package. Dipakai modal
     * generate + edit untuk checkbox picker.
     */
    #[Computed]
    public function availableScopes(): array
    {
        return app(ScopeRegistry::class)->grouped();
    }

    public function updatedSearch(): void
    {
        $this->resetPage();
    }

    public function updatedStatusFilter(): void
    {
        $this->resetPage();
    }

    // -- Generate ---------------------------------------------------------------

    public function openCreate(): void
    {
        Gate::authorize('api.token.create');
        $this->resetGenerateForm();
        $this->showCreate = true;
    }

    public function create(TokenManager $manager): void
    {
        Gate::authorize('api.token.create');

        $validated = $this->validate();

        $expiresAt = ! empty($validated['expiresAt'])
            ? Carbon::parse($validated['expiresAt'])->endOfDay()
            : null;

        // Filter scope: hanya yang benar-benar ter-register saat ini —
        // tolak input yang sudah de-register supaya tidak grant scope yatim.
        $registry = app(ScopeRegistry::class);
        $scopes = array_values(array_filter(
            $validated['selectedScopes'] ?? [],
            fn ($scope) => $registry->has($scope),
        ));

        $result = $manager->create(
            name: $validated['name'],
            scopes: $scopes,
            expiresAt: $expiresAt,
            createdBy: Auth::id(),
            allowedIps: $this->parseIpInput($validated['allowedIpsInput'] ?? ''),
            allowedOrigins: $this->parseIpInput($validated['allowedOriginsInput'] ?? ''),
        );

        // Tutup create modal → buka plaintext modal.
        $this->showCreate = false;
        $this->plaintextToken = $result['plaintext'];
        $this->plaintextTokenName = $result['token']->name;
        $this->showPlaintext = true;

        $this->resetGenerateForm();
        unset($this->tokens, $this->stats);

        $this->dispatch('toast', type: 'success', message: 'Token API berhasil dibuat. Salin sekarang — tidak akan ditampilkan lagi.');
    }

    public function closePlaintext(): void
    {
        $this->showPlaintext = false;
        $this->plaintextToken = '';
        $this->plaintextTokenName = '';
    }

    // -- Revoke -----------------------------------------------------------------

    public function revoke(int $id, TokenManager $manager): void
    {
        Gate::authorize('api.token.revoke');

        $token = ApiToken::findOrFail($id);
        $manager->revoke($token);

        unset($this->tokens, $this->stats);
        $this->dispatch('toast', type: 'success', message: "Token \"{$token->name}\" di-revoke. Request berikutnya akan ditolak.");
    }

    // -- Edit scopes ------------------------------------------------------------

    public function openEditScopes(int $id): void
    {
        Gate::authorize('api.token.create');

        $token = ApiToken::with('scopes')->findOrFail($id);

        $this->editingTokenId = $token->id;
        $this->editScopes = $token->scopeNames();
        $this->showEditScopes = true;
    }

    public function saveEditScopes(): void
    {
        Gate::authorize('api.token.create');

        $token = ApiToken::with('scopes')->findOrFail($this->editingTokenId);

        $registry = app(ScopeRegistry::class);
        $new = array_values(array_unique(array_filter(
            $this->editScopes,
            fn ($scope) => $registry->has($scope),
        )));

        $current = $token->scopeNames();

        $toAdd = array_diff($new, $current);
        $toRemove = array_diff($current, $new);

        foreach ($toAdd as $scope) {
            $token->scopes()->create(['scope' => $scope]);
        }

        if (! empty($toRemove)) {
            $token->scopes()->whereIn('scope', $toRemove)->delete();
        }

        $this->showEditScopes = false;
        $this->editingTokenId = null;
        unset($this->tokens);

        $this->dispatch('toast', type: 'success', message: 'Scope token diperbarui.');
    }

    // -- Edit IP allow-list -----------------------------------------------------

    /**
     * Buka modal edit IP allow-list untuk token tertentu. Pre-fill textarea
     * dengan daftar IP yang sekarang tersimpan, dipisah baris.
     */
    public function openEditIps(int $id): void
    {
        Gate::authorize('api.token.create');

        $token = ApiToken::findOrFail($id);

        $this->editingIpsTokenId = $token->id;
        $this->editIpsInput = is_array($token->allowed_ips) && $token->allowed_ips !== []
            ? implode("\n", $token->allowed_ips)
            : '';
        $this->resetValidation();
        $this->showEditIps = true;
    }

    public function saveEditIps(TokenManager $manager): void
    {
        Gate::authorize('api.token.create');

        $this->validate([
            'editIpsInput' => ['nullable', 'string', $this->ipListRuleFor('editIpsInput')],
        ]);

        $token = ApiToken::findOrFail($this->editingIpsTokenId);
        $manager->updateAllowedIps($token, $this->parseIpInput($this->editIpsInput));

        $this->showEditIps = false;
        $this->editingIpsTokenId = null;
        $this->editIpsInput = '';
        unset($this->tokens);

        $msg = $token->fresh()->allowed_ips
            ? 'IP allow-list diperbarui.'
            : 'IP allow-list dikosongkan — token boleh dipakai dari IP mana pun.';

        $this->dispatch('toast', type: 'success', message: $msg);
    }

    /**
     * Variant ipListRule yang melaporkan error ke attribute spesifik
     * ($field) — closure rule perlu tahu field-nya supaya pesan tampil
     * di textarea yang benar.
     */
    protected function ipListRuleFor(string $field): \Closure
    {
        return function (string $attribute, mixed $value, \Closure $fail): void {
            foreach ($this->parseIpInput((string) $value) as $entry) {
                if (! $this->isValidIpOrCidr($entry)) {
                    $fail("Entri \"{$entry}\" bukan IP atau CIDR yang valid.");
                    return;
                }
            }
        };
    }

    // -- Edit Origin allow-list -------------------------------------------------

    public function openEditOrigins(int $id): void
    {
        Gate::authorize('api.token.create');

        $token = ApiToken::findOrFail($id);

        $this->editingOriginsTokenId = $token->id;
        $this->editOriginsInput = is_array($token->allowed_origins) && $token->allowed_origins !== []
            ? implode("\n", $token->allowed_origins)
            : '';
        $this->resetValidation();
        $this->showEditOrigins = true;
    }

    public function saveEditOrigins(TokenManager $manager): void
    {
        Gate::authorize('api.token.create');

        $this->validate([
            'editOriginsInput' => ['nullable', 'string', $this->originListRule()],
        ]);

        $token = ApiToken::findOrFail($this->editingOriginsTokenId);
        $manager->updateAllowedOrigins($token, $this->parseIpInput($this->editOriginsInput));

        $this->showEditOrigins = false;
        $this->editingOriginsTokenId = null;
        $this->editOriginsInput = '';
        unset($this->tokens);

        $msg = $token->fresh()->allowed_origins
            ? 'Origin allow-list diperbarui.'
            : 'Origin allow-list dikosongkan — token boleh dipakai dari Origin mana pun.';

        $this->dispatch('toast', type: 'success', message: $msg);
    }

    // -- Helpers ----------------------------------------------------------------

    private function resetGenerateForm(): void
    {
        $this->reset(['name', 'selectedScopes', 'expiresAt', 'allowedIpsInput', 'allowedOriginsInput']);
        $this->resetValidation();
    }

    public function render()
    {
        return view('nawasara-api::livewire.pages.token.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
