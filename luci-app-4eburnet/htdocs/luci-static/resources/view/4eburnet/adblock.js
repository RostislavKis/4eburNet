'use strict';
'require view';
'require rpc';
'require ui';

var callAdblockStatus = rpc.declare({ object: '4eburnet', method: 'adblock_status' });
var callDnsSet        = rpc.declare({ object: '4eburnet', method: 'dns_set' });
var callInstallPkg    = rpc.declare({
    object: '4eburnet', method: 'install_pkg', params: ['package']
});

return view.extend({

    load: function() {
        return callAdblockStatus();
    },

    render: function(status) {
        status = status || {};

        var statusEl = E('div', {
            style: 'font-size:11px;min-height:16px;margin-top:8px'
        }, ['']);

        function showStatus(msg, ok) {
            statusEl.textContent = msg;
            statusEl.style.color = ok ? '#3ecf6a' : '#f85149';
        }

        /* Переключатель Fake-IP (основа adblock через DNS) */
        var toggleBtn = E('button', {
            class: status.enabled ? 'btn cbi-button-negative' : 'btn cbi-button',
            style: 'padding:6px 14px;font-size:12px',
            click: function() {
                var nowEnabled = toggleBtn.dataset.enabled === '1';
                var newVal     = nowEnabled ? '0' : '1';
                showStatus(_('Применение…'), true);
                callDnsSet({fake_ip_enabled: newVal}).then(function(r) {
                    if (r && r.ok) {
                        toggleBtn.dataset.enabled = newVal;
                        var isOn = newVal === '1';
                        toggleBtn.textContent = isOn
                            ? _('🔴 Выключить Fake-IP блокировку')
                            : _('🟢 Включить Fake-IP блокировку');
                        toggleBtn.className = isOn
                            ? 'btn cbi-button-negative'
                            : 'btn cbi-button';
                        badgeEl.textContent = isOn ? _('Включён') : _('Выключен');
                        badgeEl.style.color = isOn ? '#3ecf6a' : '#8d96a0';
                        showStatus('✓ ' + _('Сохранено'), true);
                    } else {
                        showStatus('✕ ' + ((r && r.error) || _('ошибка')), false);
                    }
                }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
            }
        }, [
            status.enabled
                ? _('🔴 Выключить Fake-IP блокировку')
                : _('🟢 Включить Fake-IP блокировку')
        ]);
        toggleBtn.dataset.enabled = status.enabled ? '1' : '0';

        var badgeEl = E('span', {
            style: 'font-size:11px;font-weight:600;'
                 + 'color:' + (status.enabled ? '#3ecf6a' : '#8d96a0')
        }, [status.enabled ? _('Включён') : _('Выключен')]);

        /* Установить пакет с geo-списками */
        var installStatusEl = E('div', {
            style: 'font-size:11px;min-height:16px;margin-top:6px'
        }, ['']);

        var installBtn = E('button', {
            id: 'adblock-install-btn',
            class: 'btn cbi-button',
            click: function() {
                installBtn.disabled = true;
                installStatusEl.textContent = _('Установка…');
                installStatusEl.style.color = '#8d96a0';
                callInstallPkg('4eburnet-geodata').then(function(r) {
                    installBtn.disabled = false;
                    if (r && r.ok) {
                        installStatusEl.textContent = '✓ ' + _('Установлен. Перезапустите демон.');
                        installStatusEl.style.color = '#3ecf6a';
                    } else {
                        installStatusEl.textContent = '✕ ' + ((r && r.output) || (r && r.message) || _('ошибка'));
                        installStatusEl.style.color = '#f85149';
                    }
                }).catch(function(e) { if (installBtn) installBtn.disabled = false; ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
            }
        }, [_('⬇ Установить 4eburnet-geodata')]);

        return E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:14px'},
                [_('Блокировка рекламы (DNS)')]),

            /* Статус */
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;'
                     + 'padding:14px;margin-bottom:12px'
            }, [
                E('div', {
                    style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                         + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:12px'
                }, [_('Состояние')]),

                E('div', {style: 'display:flex;gap:24px;flex-wrap:wrap;margin-bottom:12px'}, [
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:4px'},
                            [_('Fake-IP блокировка')]),
                        badgeEl
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:4px'},
                            [_('Записей в блок-листе')]),
                        E('span', {
                            style: 'font-size:11px;font-weight:600;font-family:monospace;'
                                 + 'color:' + (status.has_list ? '#e6edf3' : '#545d68')
                        }, [
                            status.ads_count > 0
                                ? String(status.ads_count)
                                : _('Список не загружен')
                        ])
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:4px'},
                            [_('Файл блок-листа')]),
                        E('code', {
                            style: 'font-size:10px;color:#bc8cff;font-family:monospace'
                        }, [status.geo_file || '/etc/4eburnet/geo/geosite-ads.lst'])
                    ])
                ]),

                E('div', {style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'}, [
                    toggleBtn,
                    statusEl
                ]),

                E('div', {
                    style: 'margin-top:10px;font-size:11px;color:#545d68;'
                         + 'border-top:1px solid #21262d;padding-top:10px'
                }, [
                    _('Принцип: DNS-запросы к доменам из блок-листа получают Fake-IP (198.18.x.x). '
                      + 'Трафик на эти адреса блокируется nftables правилами.')
                ])
            ]),

            /* Загрузка geo данных */
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:14px'
            }, [
                E('div', {
                    style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                         + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:10px'
                }, [_('Гео-данные и блок-листы')]),

                !status.has_list ? E('div', {
                    style: 'background:rgba(240,180,41,.06);border:1px solid rgba(240,180,41,.25);'
                         + 'border-radius:4px;padding:10px;margin-bottom:10px;'
                         + 'font-size:11px;color:#f0b429'
                }, [
                    _('⚠ Блок-лист отсутствует. Установите пакет 4eburnet-geodata или скопируйте '
                      + 'geosite-ads.lst в /etc/4eburnet/geo/')
                ]) : E('div', {
                    style: 'background:rgba(62,207,106,.06);border:1px solid rgba(62,207,106,.2);'
                         + 'border-radius:4px;padding:8px 10px;margin-bottom:10px;'
                         + 'font-size:11px;color:#3ecf6a'
                }, [
                    '✓ ' + _('Блок-лист загружен: ') + status.ads_count + _(' записей')
                ]),

                E('div', {style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'}, [
                    installBtn,
                    installStatusEl
                ]),

                E('div', {
                    style: 'margin-top:10px;font-size:10px;color:#545d68'
                }, [
                    _('Пакет 4eburnet-geodata содержит: geosite-ads.lst (рекламные домены), '
                      + 'geoip-ru.mmdb (Россия). Источник: v2fly/domain-list-community.')
                ])
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
