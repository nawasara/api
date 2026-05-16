<div>
    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="Scope Catalog"
            description="Daftar scope API yang ter-register oleh package domain. Dipakai saat assign scope ke token."
            :count="$this->totalScopes.' scope'" />

        @if (empty($this->scopeGroups))
            <x-nawasara-ui::empty-state icon="lucide-list-checks"
                title="Belum ada scope ter-register"
                description="Package domain (CCTV, WiFi, dll) mendaftarkan scope mereka di service provider. Pastikan package sudah ter-install dan boot." />
        @else
            <div class="space-y-6">
                @foreach ($this->scopeGroups as $group => $scopes)
                    <div class="rounded-lg border border-gray-200 bg-white shadow-sm
                                dark:border-neutral-700 dark:bg-neutral-900">
                        <div class="flex items-center justify-between border-b border-gray-200 px-5 py-3
                                    dark:border-neutral-700">
                            <h3 class="text-sm font-semibold uppercase tracking-wide text-gray-700
                                       dark:text-neutral-200">
                                {{ $group }}
                            </h3>
                            <x-nawasara-ui::badge color="neutral">
                                {{ count($scopes) }} scope
                            </x-nawasara-ui::badge>
                        </div>

                        <div class="divide-y divide-gray-100 dark:divide-neutral-800">
                            @foreach ($scopes as $scope)
                                <div class="flex items-start justify-between gap-4 px-5 py-3">
                                    <div class="min-w-0 flex-1">
                                        <code class="block font-mono text-sm font-medium text-gray-900
                                                     dark:text-neutral-100">
                                            {{ $scope['name'] }}
                                        </code>
                                        <p class="mt-0.5 text-sm text-gray-600 dark:text-neutral-400">
                                            {{ $scope['description'] }}
                                        </p>
                                    </div>
                                    <div class="shrink-0 text-right">
                                        @if ($scope['token_count'] > 0)
                                            <x-nawasara-ui::badge color="success">
                                                {{ $scope['token_count'] }} token
                                            </x-nawasara-ui::badge>
                                        @else
                                            <span class="text-xs text-gray-400 dark:text-neutral-600">
                                                belum di-grant
                                            </span>
                                        @endif
                                    </div>
                                </div>
                            @endforeach
                        </div>
                    </div>
                @endforeach
            </div>
        @endif
    </x-nawasara-ui::page.container>
</div>
