<div>
    <x-nawasara-ui::page.container>
        <x-nawasara-ui::page-header
            title="API Access Logs"
            description="Log request API 24 jam terakhir + lebih lama. Auto-prune harian sesuai retention." />

        {{-- Ringkasan 24 jam --}}
        <div class="mb-4 flex flex-wrap gap-3">
            <x-nawasara-ui::stat-card label="Request 24 jam" :value="$this->stats['total_24h']"
                icon="lucide-activity" color="info" />
            <x-nawasara-ui::stat-card label="Sukses (2xx)" :value="$this->stats['success_24h']"
                icon="lucide-check-circle" color="success" />
            <x-nawasara-ui::stat-card label="Gagal (4xx/5xx)" :value="$this->stats['failure_24h']"
                icon="lucide-x-circle" color="danger" />
            <x-nawasara-ui::stat-card label="Token Unik" :value="$this->stats['unique_tokens_24h']"
                icon="lucide-key-square" color="neutral" />
        </div>

        <x-nawasara-ui::filter-bar>
            <x-nawasara-ui::filter-dropdown
                label="Token"
                model="tokenFilter"
                :items="$this->tokenOptions" />
            <x-nawasara-ui::filter-dropdown
                label="Status"
                model="statusFilter"
                :items="['2xx' => '2xx Sukses', '4xx' => '4xx Client Error', '5xx' => '5xx Server Error']" />
            <x-nawasara-ui::filter-dropdown
                label="Kind"
                model="kindFilter"
                :items="['api' => 'Request API', 'stream_verify' => 'Stream Verify (Nginx)']" />
        </x-nawasara-ui::filter-bar>

        @if ($this->logs->isEmpty())
            <x-nawasara-ui::empty-state icon="lucide-scroll-text" title="Belum ada log"
                description="Log akan terisi otomatis saat consumer mulai memakai API." />
        @else
            <x-nawasara-ui::table
                :headers="['Waktu', 'Token', 'Method', 'Path', 'Status', 'Kind', 'IP']">
                <x-slot:table>
                    @foreach ($this->logs as $log)
                        <tr wire:key="log-{{ $log->id }}">
                            <td class="px-6 py-3 text-xs text-gray-600 dark:text-neutral-400">
                                <div title="{{ $log->created_at->toDateTimeString() }}">
                                    {{ $log->created_at->diffForHumans() }}
                                </div>
                                <div class="text-[10px] text-gray-400 dark:text-neutral-600">
                                    {{ $log->created_at->format('H:i:s') }}
                                </div>
                            </td>
                            <td class="px-6 py-3 text-sm">
                                @if ($log->token)
                                    <div class="font-medium text-gray-900 dark:text-neutral-100">
                                        {{ $log->token->name }}
                                    </div>
                                    <code class="font-mono text-[10px] text-gray-500 dark:text-neutral-500">
                                        {{ $log->token->token_prefix }}…
                                    </code>
                                @else
                                    <span class="text-xs italic text-rose-600 dark:text-rose-400">
                                        — auth gagal —
                                    </span>
                                @endif
                            </td>
                            <td class="px-6 py-3">
                                <code class="rounded bg-gray-100 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-gray-700
                                           dark:bg-neutral-800 dark:text-neutral-300">
                                    {{ $log->method }}
                                </code>
                            </td>
                            <td class="px-6 py-3 font-mono text-xs text-gray-700 dark:text-neutral-300">
                                {{ $log->path }}
                            </td>
                            <td class="px-6 py-3 text-sm">
                                @if ($log->status >= 200 && $log->status < 300)
                                    <x-nawasara-ui::badge color="success" size="xs">{{ $log->status }}</x-nawasara-ui::badge>
                                @elseif ($log->status >= 400 && $log->status < 500)
                                    <x-nawasara-ui::badge color="warning" size="xs">{{ $log->status }}</x-nawasara-ui::badge>
                                @elseif ($log->status >= 500)
                                    <x-nawasara-ui::badge color="danger" size="xs">{{ $log->status }}</x-nawasara-ui::badge>
                                @else
                                    <x-nawasara-ui::badge color="neutral" size="xs">{{ $log->status }}</x-nawasara-ui::badge>
                                @endif
                            </td>
                            <td class="px-6 py-3 text-xs text-gray-600 dark:text-neutral-400">
                                @if ($log->kind === 'stream_verify')
                                    <x-nawasara-ui::badge color="info" size="xs">stream</x-nawasara-ui::badge>
                                @else
                                    <span class="text-gray-400 dark:text-neutral-600">api</span>
                                @endif
                            </td>
                            <td class="px-6 py-3 font-mono text-xs text-gray-500 dark:text-neutral-500">
                                {{ $log->ip ?? '—' }}
                            </td>
                        </tr>
                    @endforeach
                </x-slot:table>

                <x-slot:footer>
                    <div class="px-2">
                        {{ $this->logs->links('nawasara-ui::components.pagination') }}
                    </div>
                </x-slot:footer>
            </x-nawasara-ui::table>
        @endif
    </x-nawasara-ui::page.container>
</div>
