<div>
    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="API Tokens"
            description="Token akses untuk aplikasi consumer eksternal. Setiap token punya scope per-resource & bisa di-revoke."
            :count="$this->stats['total'].' token'">
            <x-nawasara-ui::button color="primary" wire:click="openCreate" permission="api.token.create">
                <x-slot:icon><x-lucide-plus class="size-4" /></x-slot:icon>
                Generate Token
            </x-nawasara-ui::button>
        </x-nawasara-ui::page-header>

        {{-- Ringkasan status --}}
        <div class="mb-4 flex flex-wrap gap-3">
            <x-nawasara-ui::stat-card label="Aktif" :value="$this->stats['active']"
                icon="lucide-circle-check" color="success" />
            <x-nawasara-ui::stat-card label="Expired" :value="$this->stats['expired']"
                icon="lucide-clock-alert" color="warning" />
            <x-nawasara-ui::stat-card label="Di-revoke" :value="$this->stats['revoked']"
                icon="lucide-ban" color="danger" />
        </div>

        <x-nawasara-ui::filter-bar
            search-model="search"
            search-placeholder="Cari nama atau prefix token...">
            <x-nawasara-ui::filter-dropdown
                label="Status"
                model="statusFilter"
                :items="['active' => 'Aktif', 'expired' => 'Expired', 'revoked' => 'Di-revoke']" />
        </x-nawasara-ui::filter-bar>

        @if ($this->tokens->isEmpty())
            <x-nawasara-ui::empty-state icon="lucide-key-square" title="Belum ada API token"
                description="Generate token pertama untuk consumer eksternal. Setiap token bisa diatur scope-nya per resource.">
                <x-nawasara-ui::button color="primary" wire:click="openCreate" permission="api.token.create">
                    <x-slot:icon><x-lucide-plus class="size-4" /></x-slot:icon>
                    Generate Token
                </x-nawasara-ui::button>
            </x-nawasara-ui::empty-state>
        @else
            <x-nawasara-ui::table
                :headers="['Nama', 'Prefix', 'Scopes', 'Last Used', 'Expires', 'Status', 'Aksi']"
                stickyLast>
                <x-slot:table>
                    @foreach ($this->tokens as $token)
                        <tr wire:key="token-{{ $token->id }}">
                            <td class="px-6 py-4 text-sm font-medium text-gray-900 dark:text-neutral-100">
                                {{ $token->name }}
                                @if ($token->creator)
                                    <div class="text-xs text-gray-500 dark:text-neutral-400">
                                        oleh {{ $token->creator->name ?? 'Unknown' }}
                                    </div>
                                @endif
                            </td>
                            <td class="px-6 py-4">
                                <code class="rounded bg-gray-100 px-2 py-0.5 font-mono text-xs text-gray-700
                                           dark:bg-neutral-800 dark:text-neutral-300">
                                    {{ $token->token_prefix }}…
                                </code>
                            </td>
                            <td class="px-6 py-4">
                                @if ($token->scopes->isEmpty())
                                    <span class="text-xs text-gray-400 dark:text-neutral-600">— tidak ada —</span>
                                @else
                                    <div class="flex flex-wrap gap-1">
                                        @foreach ($token->scopes->take(3) as $scope)
                                            <x-nawasara-ui::badge color="neutral" size="xs">
                                                {{ $scope->scope }}
                                            </x-nawasara-ui::badge>
                                        @endforeach
                                        @if ($token->scopes->count() > 3)
                                            <x-nawasara-ui::badge color="neutral" size="xs">
                                                +{{ $token->scopes->count() - 3 }}
                                            </x-nawasara-ui::badge>
                                        @endif
                                    </div>
                                @endif
                            </td>
                            <td class="px-6 py-4 text-xs text-gray-600 dark:text-neutral-400">
                                @if ($token->last_used_at)
                                    <div title="{{ $token->last_used_at->toDateTimeString() }}">
                                        {{ $token->last_used_at->diffForHumans() }}
                                    </div>
                                    @if ($token->last_used_ip)
                                        <div class="font-mono text-[10px] text-gray-400 dark:text-neutral-600">
                                            {{ $token->last_used_ip }}
                                        </div>
                                    @endif
                                @else
                                    <span class="text-gray-400 dark:text-neutral-600">belum pernah</span>
                                @endif
                            </td>
                            <td class="px-6 py-4 text-xs text-gray-600 dark:text-neutral-400">
                                @if ($token->expires_at)
                                    <span title="{{ $token->expires_at->toDateTimeString() }}">
                                        {{ $token->expires_at->format('d M Y') }}
                                    </span>
                                @else
                                    <span class="text-gray-400 dark:text-neutral-600">tidak expired</span>
                                @endif
                            </td>
                            <td class="px-6 py-4 text-sm">
                                @if ($token->isRevoked())
                                    <x-nawasara-ui::badge color="danger" icon="lucide-ban">revoked</x-nawasara-ui::badge>
                                @elseif ($token->isExpired())
                                    <x-nawasara-ui::badge color="warning" icon="lucide-clock-alert">expired</x-nawasara-ui::badge>
                                @else
                                    <x-nawasara-ui::badge color="success" icon="lucide-circle-check">aktif</x-nawasara-ui::badge>
                                @endif
                            </td>
                            <td class="px-6 py-4">
                                <div class="flex justify-end gap-1">
                                    @can('api.token.create')
                                        <x-nawasara-ui::icon-button icon="settings-2" tooltip="Ubah scope"
                                            wire:click="openEditScopes({{ $token->id }})" />
                                        <x-nawasara-ui::icon-button icon="shield"
                                            tooltip="{{ $token->allowed_ips ? 'IP allow-list aktif — '.count($token->allowed_ips).' entri' : 'IP allow-list kosong (boleh dari mana saja)' }}"
                                            wire:click="openEditIps({{ $token->id }})" />
                                    @endcan
                                    @can('api.token.revoke')
                                        @unless ($token->isRevoked())
                                            <x-nawasara-ui::icon-button icon="ban" tooltip="Revoke token"
                                                wire:click="revoke({{ $token->id }})"
                                                wire:confirm="Revoke token {{ $token->name }}? Request berikutnya akan ditolak — tidak bisa di-undo." />
                                        @endunless
                                    @endcan
                                </div>
                            </td>
                        </tr>
                    @endforeach
                </x-slot:table>

                <x-slot:footer>
                    <div class="px-2">
                        {{ $this->tokens->links('nawasara-ui::components.pagination') }}
                    </div>
                </x-slot:footer>
            </x-nawasara-ui::table>
        @endif
    </x-nawasara-ui::page.container>

    {{-- =========================================================== --}}
    {{-- Generate token modal                                         --}}
    {{-- =========================================================== --}}
    <x-nawasara-ui::modal wire:model="showCreate" maxWidth="2xl"
        title="Generate API Token"
        subtitle="Token plaintext akan ditampilkan SEKALI setelah dibuat. Pastikan langsung disalin.">
        <form wire:submit="create" class="space-y-4">
            <div>
                <x-nawasara-ui::form.input label="Nama Token" wire:model="name"
                    placeholder="Smart City Dashboard" />
                <p class="mt-1 text-xs text-gray-500 dark:text-neutral-400">
                    Label internal untuk identifikasi aplikasi consumer. Tidak terlihat oleh consumer.
                </p>
                @error('name') <p class="mt-1 text-xs text-rose-600">{{ $message }}</p> @enderror
            </div>

            <div>
                <x-nawasara-ui::form.input type="date" label="Expires At (opsional)"
                    wire:model="expiresAt" />
                <p class="mt-1 text-xs text-gray-500 dark:text-neutral-400">
                    Kosongkan untuk token tanpa expiry. Token tetap bisa di-revoke kapan saja.
                </p>
                @error('expiresAt') <p class="mt-1 text-xs text-rose-600">{{ $message }}</p> @enderror
            </div>

            <div>
                <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
                    IP Allow-list (opsional)
                </label>
                <textarea wire:model="allowedIpsInput" rows="3"
                    placeholder="103.10.20.30&#10;103.10.20.0/24&#10;2001:db8::/32"
                    class="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono
                           focus:border-emerald-500 focus:ring-emerald-500
                           dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"></textarea>
                <p class="mt-1 text-xs text-gray-500 dark:text-neutral-400">
                    Satu entri per baris atau dipisah koma. Dukung IPv4, IPv6, dan CIDR
                    (mis. <code>10.0.0.0/8</code>). Kosongkan untuk tidak membatasi IP.
                </p>
                @error('allowedIpsInput') <p class="mt-1 text-xs text-rose-600">{{ $message }}</p> @enderror
            </div>

            <div>
                <div class="mb-2 flex items-center justify-between">
                    <label class="text-sm font-medium text-gray-700 dark:text-gray-300">
                        Scopes
                    </label>
                    <span class="text-xs text-gray-500 dark:text-neutral-400">
                        Pilih scope yang token ini boleh akses
                    </span>
                </div>

                @if (empty($this->availableScopes))
                    <div class="rounded-md border border-dashed border-gray-300 px-4 py-6 text-center text-sm text-gray-500
                                dark:border-neutral-700 dark:text-neutral-400">
                        Belum ada scope ter-register. Package domain (CCTV, WiFi, dll) belum mendaftarkan scope ke registry.
                    </div>
                @else
                    <div class="max-h-80 space-y-3 overflow-y-auto rounded-md border border-gray-200 p-4
                                dark:border-neutral-700">
                        @foreach ($this->availableScopes as $group => $scopes)
                            <div>
                                <div class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500
                                            dark:text-neutral-400">
                                    {{ $group }}
                                </div>
                                <div class="space-y-1.5">
                                    @foreach ($scopes as $scope)
                                        <label class="flex items-start gap-2 rounded px-2 py-1 text-sm
                                                      hover:bg-gray-50 dark:hover:bg-neutral-800/50">
                                            <input type="checkbox" wire:model.live="selectedScopes"
                                                value="{{ $scope['name'] }}"
                                                class="mt-0.5 rounded border-gray-300 text-emerald-700 focus:ring-emerald-700">
                                            <div class="flex-1">
                                                <code class="font-mono text-xs text-gray-900 dark:text-neutral-100">
                                                    {{ $scope['name'] }}
                                                </code>
                                                <div class="text-xs text-gray-500 dark:text-neutral-400">
                                                    {{ $scope['description'] }}
                                                </div>
                                            </div>
                                        </label>
                                    @endforeach
                                </div>
                            </div>
                        @endforeach
                    </div>
                @endif
            </div>

            <div class="flex justify-end gap-2 pt-2">
                <x-nawasara-ui::button type="button" variant="ghost" color="secondary"
                    wire:click="$set('showCreate', false)">
                    Batal
                </x-nawasara-ui::button>
                <x-nawasara-ui::button type="submit" color="primary">
                    Generate Token
                </x-nawasara-ui::button>
            </div>
        </form>
    </x-nawasara-ui::modal>

    {{-- =========================================================== --}}
    {{-- Plaintext one-time-show modal                                --}}
    {{-- =========================================================== --}}
    <x-nawasara-ui::modal wire:model="showPlaintext" maxWidth="2xl"
        :title="'Token: '.$plaintextTokenName"
        subtitle="Salin token ini SEKARANG. Setelah modal ditutup, plaintext token TIDAK akan ditampilkan lagi.">
        <div class="space-y-4">
            <div class="flex items-start gap-3 rounded-md border-l-4 border-amber-400 bg-amber-50 p-3
                        dark:border-amber-500 dark:bg-amber-900/20">
                <x-lucide-triangle-alert class="size-5 shrink-0 text-amber-600 dark:text-amber-400" />
                <div class="text-sm text-amber-900 dark:text-amber-200">
                    <strong>Token plaintext tidak disimpan di server.</strong>
                    Kalau hilang sebelum diberikan ke consumer, Anda harus generate token baru
                    dan revoke yang ini.
                </div>
            </div>

            <div
                x-data="{
                    copied: false,
                    copy() {
                        const text = $refs.tok.textContent.trim();
                        navigator.clipboard.writeText(text).then(() => {
                            this.copied = true;
                            setTimeout(() => this.copied = false, 2000);
                        });
                    }
                }"
                class="relative"
            >
                <div class="overflow-x-auto rounded-md border border-gray-200 bg-gray-50 p-3 pr-12 font-mono text-sm text-gray-900
                            dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100"
                     x-ref="tok">{{ $plaintextToken }}</div>

                <button type="button" x-on:click="copy()"
                    class="absolute right-2 top-2 inline-flex items-center gap-1 rounded-md border border-gray-200
                           bg-white px-2 py-1 text-xs text-gray-700 hover:bg-gray-50
                           dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800">
                    <template x-if="!copied">
                        <span class="inline-flex items-center gap-1">
                            <x-lucide-copy class="size-3.5" />
                            Salin
                        </span>
                    </template>
                    <template x-if="copied">
                        <span class="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                            <x-lucide-check class="size-3.5" />
                            Tersalin
                        </span>
                    </template>
                </button>
            </div>

            <div class="rounded-md border border-gray-200 bg-gray-50 p-3 text-xs text-gray-600
                        dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-400">
                <p class="mb-1 font-semibold text-gray-700 dark:text-neutral-300">Cara pakai:</p>
                <code class="block whitespace-pre-wrap">curl -H "Authorization: Bearer {{ $plaintextToken }}" \
     {{ url('/api/v1/me') }}</code>
            </div>

            <div class="flex justify-end pt-2">
                <x-nawasara-ui::button type="button" color="primary" wire:click="closePlaintext">
                    Saya sudah salin
                </x-nawasara-ui::button>
            </div>
        </div>
    </x-nawasara-ui::modal>

    {{-- =========================================================== --}}
    {{-- Edit scope modal                                             --}}
    {{-- =========================================================== --}}
    <x-nawasara-ui::modal wire:model="showEditScopes" maxWidth="2xl"
        title="Ubah Scope Token"
        subtitle="Tambah atau cabut scope. Token tetap valid — yang berubah hanya akses ke resource.">
        <form wire:submit="saveEditScopes" class="space-y-4">
            @if (empty($this->availableScopes))
                <div class="rounded-md border border-dashed border-gray-300 px-4 py-6 text-center text-sm text-gray-500
                            dark:border-neutral-700 dark:text-neutral-400">
                    Belum ada scope ter-register.
                </div>
            @else
                <div class="max-h-80 space-y-3 overflow-y-auto rounded-md border border-gray-200 p-4
                            dark:border-neutral-700">
                    @foreach ($this->availableScopes as $group => $scopes)
                        <div>
                            <div class="mb-1 text-xs font-semibold uppercase tracking-wide text-gray-500
                                        dark:text-neutral-400">
                                {{ $group }}
                            </div>
                            <div class="space-y-1.5">
                                @foreach ($scopes as $scope)
                                    <label class="flex items-start gap-2 rounded px-2 py-1 text-sm
                                                  hover:bg-gray-50 dark:hover:bg-neutral-800/50">
                                        <input type="checkbox" wire:model.live="editScopes"
                                            value="{{ $scope['name'] }}"
                                            class="mt-0.5 rounded border-gray-300 text-emerald-700 focus:ring-emerald-700">
                                        <div class="flex-1">
                                            <code class="font-mono text-xs text-gray-900 dark:text-neutral-100">
                                                {{ $scope['name'] }}
                                            </code>
                                            <div class="text-xs text-gray-500 dark:text-neutral-400">
                                                {{ $scope['description'] }}
                                            </div>
                                        </div>
                                    </label>
                                @endforeach
                            </div>
                        </div>
                    @endforeach
                </div>
            @endif

            <div class="flex justify-end gap-2 pt-2">
                <x-nawasara-ui::button type="button" variant="ghost" color="secondary"
                    wire:click="$set('showEditScopes', false)">
                    Batal
                </x-nawasara-ui::button>
                <x-nawasara-ui::button type="submit" color="primary">
                    Simpan Scope
                </x-nawasara-ui::button>
            </div>
        </form>
    </x-nawasara-ui::modal>

    {{-- =========================================================== --}}
    {{-- Edit IP allow-list modal                                     --}}
    {{-- =========================================================== --}}
    <x-nawasara-ui::modal wire:model="showEditIps" maxWidth="2xl"
        title="Edit IP Allow-list"
        subtitle="Batasi IP/CIDR yang boleh memakai token ini. Kosongkan untuk tidak membatasi.">
        <form wire:submit="saveEditIps" class="space-y-4">
            <div>
                <textarea wire:model="editIpsInput" rows="6"
                    placeholder="103.10.20.30&#10;103.10.20.0/24&#10;2001:db8::/32"
                    class="block w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono
                           focus:border-emerald-500 focus:ring-emerald-500
                           dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-100"></textarea>
                <p class="mt-1 text-xs text-gray-500 dark:text-neutral-400">
                    Satu entri per baris atau dipisah koma. Dukung IPv4, IPv6, dan CIDR
                    (mis. <code>10.0.0.0/8</code>, <code>2001:db8::/32</code>).
                </p>
                @error('editIpsInput') <p class="mt-1 text-xs text-rose-600">{{ $message }}</p> @enderror
            </div>

            <div class="flex justify-end gap-2 pt-2">
                <x-nawasara-ui::button type="button" variant="ghost" color="secondary"
                    wire:click="$set('showEditIps', false)">
                    Batal
                </x-nawasara-ui::button>
                <x-nawasara-ui::button type="submit" color="primary">
                    Simpan IP Allow-list
                </x-nawasara-ui::button>
            </div>
        </form>
    </x-nawasara-ui::modal>
</div>
