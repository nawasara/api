<?php

$prefix = 'nawasara-api';

return [
    [
        'workspace' => 'public-api',
        'label' => 'Public API',
        'icon' => 'lucide-plug-zap',
        'group' => 'Pengaturan',
        'url' => '',
        'permission' => 'api.token.view',
        'submenu' => [
            [
                'label' => 'API Tokens',
                'icon' => 'lucide-key-square',
                'url' => url($prefix.'/tokens'),
                'permission' => 'api.token.view',
                'navigate' => true,
            ],
            [
                'label' => 'Scopes',
                'icon' => 'lucide-list-checks',
                'url' => url($prefix.'/scopes'),
                'permission' => 'api.token.view',
                'navigate' => true,
            ],
            [
                'label' => 'Access Logs',
                'icon' => 'lucide-scroll-text',
                'url' => url($prefix.'/access-logs'),
                'permission' => 'api.token.view',
                'navigate' => true,
            ],
        ],
    ],
];
