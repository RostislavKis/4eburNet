'use strict';
'require view';
'require rpc';
'require ui';

var callImport = rpc.declare({
    object: '4eburnet',
    method: 'subscription_import',
    params: ['url', 'content', 'format', 'no_rules', 'no_groups', 'max_rules']
});

var callProviders = rpc.declare({
    object: '4eburnet',
    method: 'providers'
});

return view.extend({
    load: function() {
        return callProviders();
    },

    render: function(data) {
        var providers = (data || {}).providers || [];

        var urlInput = E('input', {
            id: 'sub-url', type: 'text',
            placeholder: 'https://sub.example.com/sub?token=...',
            style: 'width:100%;padding:6px 10px;background:#21262d;'
                 + 'border:1px solid #30363d;border-radius:4px;'
                 + 'color:#e6edf3;font-size:12px;font-family:monospace;'
                 + 'outline:none;box-sizing:border-box'
        });

        var fmtSelect = E('select', {
            id: 'sub-fmt',
            style: 'padding:6px 10px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:12px;cursor:pointer'
        }, [
            E('option', {value: 'auto'},    ['Авто-определение']),
            E('option', {value: 'clash'},   ['Clash / Mihomo YAML']),
            E('option', {value: 'base64'},  ['base64 URI список']),
            E('option', {value: 'urilist'}, ['URI список (plain)']),
            E('option', {value: 'singbox'}, ['sing-box JSON']),
        ]);

        var noRules  = E('input', {type: 'checkbox', id: 'sub-norules'});
        var noGroups = E('input', {type: 'checkbox', id: 'sub-nogroups'});
        var maxRules = E('input', {
            type: 'number', id: 'sub-maxrules',
            value: '256', min: '1', max: '512',
            style: 'width:80px;padding:4px 8px;background:#21262d;'
                 + 'border:1px solid #30363d;border-radius:4px;'
                 + 'color:#e6edf3;font-size:12px;font-family:monospace'
        });

        var importStatus = E('div', {
            id: 'import-status',
            style: 'font-size:12px;min-height:20px;margin-top:8px'
        }, ['']);

        var importBtn = E('button', {
            class: 'btn cbi-button',
            click: function() {
                var url = document.getElementById('sub-url').value.trim();
                if (!url) {
                    importStatus.style.color = '#f85149';
                    importStatus.textContent = '✕ Введите URL подписки';
                    return;
                }
                if (!/^https?:\/\//i.test(url)) {
                    importStatus.style.color = '#f85149';
                    importStatus.textContent = '✕ URL должен начинаться с http:// или https://';
                    return;
                }

                importBtn.disabled = true;
                importStatus.style.color = '#8d96a0';
                importStatus.textContent = '⏳ Загрузка и конвертация...';

                callImport(
                    url,
                    '',
                    document.getElementById('sub-fmt').value,
                    document.getElementById('sub-norules').checked ? 1 : 0,
                    document.getElementById('sub-nogroups').checked ? 1 : 0,
                    parseInt(document.getElementById('sub-maxrules').value) || 256
                ).then(function(r) {
                    importBtn.disabled = false;
                    if (r && r.ok) {
                        importStatus.style.color = '#3ecf6a';
                        importStatus.textContent = '✓ ' + r.message;
                    } else {
                        importStatus.style.color = '#f85149';
                        importStatus.textContent = '✕ ' + (r && r.error || 'неизвестная ошибка');
                    }
                }).catch(function(err) {
                    importBtn.disabled = false;
                    importStatus.style.color = '#f85149';
                    importStatus.textContent = '✕ RPC ошибка: ' + String(err);
                });
            }
        }, ['📥 Импортировать']);

        return E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;'
                + 'color:#e6edf3;margin-bottom:14px'}, ['Подписки']),

            // Форма импорта
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;'
                     + 'border-radius:5px;padding:14px;margin-bottom:12px'
            }, [
                E('div', {style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                    + 'text-transform:uppercase;letter-spacing:.7px;'
                    + 'margin-bottom:12px'}, ['Импорт подписки']),

                E('div', {style: 'margin-bottom:10px'}, [
                    E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:4px'},
                        'URL подписки (Clash / base64 / sing-box)'),
                    urlInput
                ]),

                E('div', {style: 'display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px'}, [
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:4px'}, 'Формат'),
                        fmtSelect
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:4px'}, 'Макс. правил'),
                        maxRules
                    ])
                ]),

                E('div', {style: 'display:flex;gap:16px;margin-bottom:12px'}, [
                    E('label', {style: 'display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer'}, [
                        noRules,
                        E('span', {style: 'color:#e6edf3'}, 'Не импортировать правила')
                    ]),
                    E('label', {style: 'display:flex;align-items:center;gap:6px;font-size:12px;cursor:pointer'}, [
                        noGroups,
                        E('span', {style: 'color:#e6edf3'}, 'Не импортировать группы')
                    ])
                ]),

                E('div', {style: 'display:flex;align-items:center;gap:10px'}, [
                    importBtn, importStatus
                ])
            ]),

            // Активные провайдеры
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;'
                     + 'border-radius:5px;padding:14px'
            }, [
                E('div', {style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                    + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:10px'},
                    ['Провайдеры (' + providers.length + ')']),
                providers.length === 0
                    ? E('div', {style: 'font-size:11px;color:#545d68'}, ['Провайдеры не настроены'])
                    : E('div', {},
                        providers.map(function(p) {
                            return E('div', {
                                style: 'display:flex;align-items:center;'
                                     + 'gap:10px;padding:7px 0;'
                                     + 'border-bottom:1px solid #21262d'
                            }, [
                                E('div', {style: 'width:7px;height:7px;border-radius:50%;flex-shrink:0;'
                                    + 'background:' + (p.loaded ? '#3ecf6a' : '#545d68')}),
                                E('div', {style: 'flex:1;font-size:12px;color:#e6edf3'}, [p.name]),
                                E('div', {style: 'font-size:10px;color:#545d68'}, [
                                    p.rule_count + ' правил'
                                ])
                            ]);
                        })
                    )
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave:      null,
    handleReset:     null
});
