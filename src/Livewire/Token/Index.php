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

    // -- Plaintext modal — ditampilkan SEKALI setelah generate -----------------
    public bool $showPlaintext = false;
    public string $plaintextToken = '';
    public string $plaintextTokenName = '';

    // -- Edit scope modal ------------------------------------------------------
    public bool $showEditScopes = false;
    public ?int $editingTokenId = null;
    public array $editScopes = [];

    protected function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'selectedScopes' => ['array'],
            'selectedScopes.*' => ['string'],
            'expiresAt' => ['nullable', 'date', 'after:today'],
        ];
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

    // -- Helpers ----------------------------------------------------------------

    private function resetGenerateForm(): void
    {
        $this->reset(['name', 'selectedScopes', 'expiresAt']);
        $this->resetValidation();
    }

    public function render()
    {
        return view('nawasara-api::livewire.pages.token.index')
            ->layout('nawasara-ui::components.layouts.app');
    }
}
