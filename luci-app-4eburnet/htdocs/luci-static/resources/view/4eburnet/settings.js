'use strict';
'require view';
'require rpc';
'require ui';

var callCfgGet    = rpc.declare({ object: '4eburnet', method: 'config_get',   params: ['section'] });
var callCfgSet    = rpc.declare({ object: '4eburnet', method: 'config_set',   params: ['section', 'values'] });
var callPkgMgr    = rpc.declare({ object: '4eburnet', method: 'pkg_manager' });
var callTproxy    = rpc.declare({ object: '4eburnet', method: 'tproxy_status' });
var callInstallPkg= rpc.declare({ object: '4eburnet', method: 'install_pkg',  params: ['package'] });
var callBackup    = rpc.declare({ object: '4eburnet', method: 'backup' });
var callRestore   = rpc.declare({ object: '4eburnet', method: 'restore',      params: ['path'] });
var callBkpStatus = rpc.declare({ object: '4eburnet', method: 'backup_status' });
var callReload    = rpc.declare({ object: '4eburnet', method: 'reload' });
var callRestart   = rpc.declare({ object: '4eburnet', method: 'restart' });

function sel(id) { return document.getElementById(id); }

function mkInput(id, val, mono) {
    return E('input', {
        id: id, type: 'text', value: val || '',
        style: 'width:100%;padding:6px 10px;background:#21262d;'
             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
             + 'font-size:12px;'
             + (mono ? 'font-family:monospace,' : '')
             + 'inherit;outline:none;box-sizing:border-box'
    });
}

function mkSelect(id, options, current) {
    var el = E('select', {
        id: id,
        style: 'padding:6px 10px;background:#21262d;border:1px solid #30363d;'
             + 'border-radius:4px;color:#e6edf3;font-size:12px;width:100%;cursor:pointer'
    });
    options.forEach(function(opt) {
        el.appendChild(E('option', {
            value: opt.value,
            selected: opt.value === current ? '' : null
        }, [opt.label]));
    });
    return el;
}

function mkRow(label, content) {
    return E('div', {
        style: 'display:flex;gap:12px;margin-bottom:10px;align-items:flex-start'
    }, [
        E('div', {style: 'min-width:180px;font-size:11px;color:#8d96a0;padding-top:8px;flex-shrink:0'}, [label]),
        E('div', {style: 'flex:1;min-width:0'}, [content])
    ]);
}

function card(title, rows) {
    return E('div', {
        style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;'
             + 'padding:16px;margin-bottom:14px'
    }, [
        E('div', {
            style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                 + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:14px'
        }, [title]),
        E('div', {}, rows)
    ]);
}

return view.extend({

    load: function() {
        return Promise.all([
            callCfgGet('main'),
            callPkgMgr(),
            callBkpStatus(),
            callTproxy()
        ]);
    },

    render: function(data) {
        var cfg    = data[0] || {};
        var pkg    = data[1] || { manager: 'opkg', version: '' };
        var bkp    = data[2] || { exists: false };
        var tproxy = data[3] || { available: false };

        var node = E('div', {}, [

            /* Основные параметры */
            card('⚙️ Основные параметры', [
                mkRow(_('Включить демон'),
                    E('div', {style: 'display:flex;align-items:center;gap:10px'}, [
                        E('input', {
                            type: 'checkbox', id: 'cfg-enabled',
                            checked: cfg.enabled !== '0' ? '' : null,
                            style: 'width:16px;height:16px;cursor:pointer'
                        }),
                        E('span', {style: 'font-size:12px;color:#e6edf3'}, [_('Запускать 4eburnetd')])
                    ])
                ),
                mkRow(_('Режим маршрутизации'),
                    mkSelect('cfg-mode', [
                        { value: 'rules',  label: _('rules — по правилам (рекомендуется)') },
                        { value: 'global', label: _('global — весь трафик через прокси') },
                        { value: 'direct', label: _('direct — без прокси') }
                    ], cfg.mode || 'rules')
                ),
                mkRow(_('Уровень логирования'),
                    mkSelect('cfg-loglevel', [
                        { value: 'debug', label: 'debug — ' + _('всё') },
                        { value: 'info',  label: 'info — '  + _('стандартный') },
                        { value: 'warn',  label: 'warn — '  + _('предупреждения') },
                        { value: 'error', label: 'error — ' + _('только ошибки') }
                    ], cfg.log_level || 'info')
                ),
                mkRow(_('LAN интерфейс'), mkInput('cfg-lan', cfg.lan_interface || 'br-lan', true)),
                mkRow(_('Регион (GeoIP)'),
                    mkSelect('cfg-region', [
                        { value: 'ru', label: 'RU — ' + _('Россия') },
                        { value: 'cn', label: 'CN — ' + _('Китай') },
                        { value: 'us', label: 'US — ' + _('США') }
                    ], cfg.region || 'ru')
                ),
                E('div', { style: 'margin-top:14px;display:flex;gap:8px;flex-wrap:wrap' }, [
                    E('button', {
                        class: 'btn cbi-button',
                        click: function() {
                            var values = {
                                enabled:       sel('cfg-enabled') && sel('cfg-enabled').checked ? '1' : '0',
                                mode:          sel('cfg-mode').value,
                                log_level:     sel('cfg-loglevel').value,
                                lan_interface: sel('cfg-lan').value,
                                region:        sel('cfg-region').value
                            };
                            callCfgSet('main', values).then(function(r) {
                                if (r && r.ok) {
                                    callReload();
                                    ui.addNotification(null, E('p', {}, [_('Настройки сохранены')]), 'info');
                                }
                            });
                        }
                    }, [_('💾 Сохранить')]),
                    E('button', {
                        class: 'btn cbi-button-negative',
                        click: function() {
                            if (confirm(_('Перезапустить демон?'))) {
                                callRestart().then(function() {
                                    ui.addNotification(null, E('p', {}, [_('Демон перезапущен')]), 'info');
                                });
                            }
                        }
                    }, [_('↺ Рестарт')])
                ])
            ]),

            /* OpenWrt / Пакетный менеджер */
            card('📦 OpenWrt / Пакетный менеджер', [
                mkRow(_('Версия OpenWrt'),
                    E('span', { style: 'font-family:monospace;font-size:12px;color:#ff8c5a' },
                        [pkg.version || '—'])
                ),
                mkRow(_('Пакетный менеджер'),
                    E('span', { style: 'font-family:monospace;font-size:13px;font-weight:600;color:#4aa8f0' },
                        [pkg.manager || 'opkg'])
                ),
                mkRow(_('Команда установки'),
                    E('code', { style: 'font-family:monospace;font-size:11px;color:#bc8cff' },
                        [pkg.install || 'opkg install'])
                ),
                /* kmod-nft-tproxy статус */
                !tproxy.available
                ? E('div', {
                    style: 'background:rgba(240,180,41,.06);border:1px solid rgba(240,180,41,.3);'
                         + 'border-radius:4px;padding:12px;margin-top:10px'
                  }, [
                    E('div', { style: 'color:#f0b429;font-size:12px;font-weight:600;margin-bottom:6px' },
                        [_('⚠ kmod-nft-tproxy не установлен')]),
                    E('div', { style: 'font-size:11px;color:#8d96a0;margin-bottom:8px' },
                        [_('TPROXY перехват трафика недоступен. Установите пакет:')]),
                    E('code', { style: 'display:block;font-family:monospace;font-size:11px;'
                              + 'color:#bc8cff;background:#21262d;padding:4px 8px;'
                              + 'border-radius:3px;margin-bottom:10px' },
                        [(pkg.install || 'opkg install') + ' kmod-nft-tproxy']),
                    E('button', {
                        id: 'install-tproxy-btn',
                        class: 'btn cbi-button',
                        click: function() {
                            var btn = sel('install-tproxy-btn');
                            var st  = sel('install-tproxy-status');
                            if (btn) btn.disabled = true;
                            if (st) st.textContent = _('Установка…');
                            callInstallPkg('kmod-nft-tproxy').then(function(r) {
                                if (btn) btn.disabled = false;
                                if (r && r.ok) {
                                    if (st) { st.textContent = _('✓ Установлен. Перезагрузите роутер.'); st.style.color = '#3ecf6a'; }
                                } else {
                                    var msg = (r && r.output ? r.output.substring(0, 120) : _('ошибка'));
                                    if (st) { st.textContent = _('✕ ') + msg; st.style.color = '#f85149'; }
                                }
                            });
                        }
                    }, [_('⬇ Установить kmod-nft-tproxy')]),
                    E('div', { id: 'install-tproxy-status',
                        style: 'font-size:11px;margin-top:8px;min-height:16px' }, [''])
                  ])
                : E('div', {
                    style: 'background:rgba(62,207,106,.06);border:1px solid rgba(62,207,106,.2);'
                         + 'border-radius:4px;padding:8px 12px;margin-top:10px'
                  }, [
                    E('span', { style: 'color:#3ecf6a;font-size:12px' }, [_('✓ kmod-nft-tproxy загружен')])
                  ])
            ]),

            /* Резервное копирование */
            card('💾 Резервное копирование / Восстановление', [
                E('div', { style: 'font-size:11px;color:#8d96a0;margin-bottom:12px' }, [
                    _('Бэкап UCI конфига (/etc/config/4eburnet) в /tmp/4eburnet-backup.tar.gz')
                ]),

                /* Статус существующего бэкапа */
                E('div', {
                    style: 'background:#21262d;border:1px solid #30363d;border-radius:4px;'
                         + 'padding:10px 12px;margin-bottom:12px;'
                         + 'display:flex;align-items:center;justify-content:space-between;gap:10px'
                }, [
                    E('div', {}, [
                        E('div', { style: 'font-size:12px;font-weight:600;color:#e6edf3' }, [
                            bkp.exists ? _('Бэкап на роутере') : _('Бэкап не найден')
                        ]),
                        E('div', { style: 'font-size:11px;color:#8d96a0;margin-top:2px' }, [
                            bkp.exists
                                ? '/tmp/4eburnet-backup.tar.gz (' + Math.floor((bkp.size || 0) / 1024) + ' KB)'
                                : _('Нет сохранённого бэкапа')
                        ])
                    ]),
                    bkp.exists ? E('a', {
                        href: '/tmp/4eburnet-backup.tar.gz',
                        download: '4eburnet-backup.tar.gz',
                        class: 'btn cbi-button',
                        style: 'padding:5px 10px;font-size:11px;text-decoration:none;flex-shrink:0'
                    }, [_('⬇ Скачать')]) : E('span')
                ]),

                /* Кнопки создания бэкапа */
                E('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;margin-bottom:8px' }, [
                    E('button', {
                        id: 'backup-btn',
                        class: 'btn cbi-button',
                        click: function() {
                            var btn = sel('backup-btn');
                            var st  = sel('backup-result');
                            if (btn) btn.disabled = true;
                            if (st) st.textContent = _('Создание бэкапа…');
                            callBackup().then(function(r) {
                                if (btn) btn.disabled = false;
                                if (r && r.ok) {
                                    if (st) { st.textContent = '✓ ' + r.message; st.style.color = '#3ecf6a'; }
                                    var dl = sel('backup-dl');
                                    if (dl) dl.style.display = '';
                                } else {
                                    if (st) { st.textContent = '✕ ' + (r && r.error || _('ошибка')); st.style.color = '#f85149'; }
                                }
                            });
                        }
                    }, [_('📦 Создать бэкап')]),
                    E('a', {
                        id: 'backup-dl',
                        href: '/tmp/4eburnet-backup.tar.gz',
                        download: '4eburnet-backup.tar.gz',
                        class: 'btn cbi-button',
                        style: (bkp.exists ? '' : 'display:none;') + 'padding:5px 10px;font-size:11px;text-decoration:none'
                    }, [_('⬇ Скачать бэкап')])
                ]),
                E('div', { id: 'backup-result', style: 'font-size:11px;margin-bottom:16px;min-height:16px' }, ['']),

                /* Восстановление */
                E('div', { style: 'border-top:1px solid #30363d;padding-top:14px' }, [
                    E('div', { style: 'font-size:12px;font-weight:600;color:#e6edf3;margin-bottom:10px' }, [
                        _('Восстановить из /tmp/4eburnet-backup.tar.gz')
                    ]),
                    E('div', { style: 'font-size:11px;color:#8d96a0;margin-bottom:10px' }, [
                        _('Загрузите бэкап на роутер в /tmp/, затем нажмите «Восстановить».')
                    ]),
                    E('button', {
                        id: 'restore-btn',
                        class: 'btn cbi-button-negative',
                        click: function() {
                            var st = sel('restore-result');
                            if (!confirm(_('Восстановить конфиг из /tmp/4eburnet-backup.tar.gz? Текущий конфиг будет перезаписан.'))) return;
                            var btn = sel('restore-btn');
                            if (btn) btn.disabled = true;
                            if (st) st.textContent = _('Восстановление…');
                            callRestore('/tmp/4eburnet-backup.tar.gz').then(function(r) {
                                if (btn) btn.disabled = false;
                                if (r && r.ok) {
                                    if (st) { st.textContent = '✓ ' + r.message; st.style.color = '#3ecf6a'; }
                                } else {
                                    if (st) { st.textContent = '✕ ' + (r && r.error || _('ошибка')); st.style.color = '#f85149'; }
                                }
                            });
                        }
                    }, [_('↺ Восстановить')]),
                    E('div', { id: 'restore-result', style: 'font-size:11px;margin-top:8px;min-height:16px' }, [''])
                ])
            ])
        ]);

        return node;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
