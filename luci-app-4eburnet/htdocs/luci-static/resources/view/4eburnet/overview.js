'use strict';
'require view';
'require rpc';
'require poll';

var callStatus = rpc.declare({
    object: '4eburnet',
    method: 'status'
});
var callStats = rpc.declare({
    object: '4eburnet',
    method: 'stats'
});
var callGroups = rpc.declare({
    object: '4eburnet',
    method: 'groups'
});
var callWanIp = rpc.declare({
    object: '4eburnet',
    method: 'wan_ip'
});
var callTproxyStatus = rpc.declare({
    object: '4eburnet',
    method: 'tproxy_status'
});
var callReload = rpc.declare({
    object: '4eburnet',
    method: 'reload'
});
var callRestart = rpc.declare({
    object: '4eburnet',
    method: 'restart'
});
var callStop = rpc.declare({
    object: '4eburnet',
    method: 'stop'
});

function fmtUptime(sec) {
    sec = sec || 0;
    return Math.floor(sec / 3600) + 'ч '
         + Math.floor(sec % 3600 / 60) + 'м '
         + (sec % 60) + 'с';
}

function badge(text, cls) {
    return E('span', {
        class: 'eb-badge eb-' + cls,
        style: 'display:inline-block;padding:2px 7px;border-radius:3px;'
             + 'font-size:10px;font-weight:600;margin-right:4px'
    }, [text]);
}

function statusCard(label, valueId, subId, colorCls) {
    return E('div', {
        style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;'
             + 'padding:12px 14px;' + (colorCls === 'ok' ? 'border-color:rgba(62,207,106,.25)' : '')
    }, [
        E('div', {style: 'font-size:10px;color:#545d68;text-transform:uppercase;letter-spacing:.05em'}, [label]),
        E('div', {id: valueId, style: 'font-size:18px;font-weight:700;margin-top:4px'}, ['—']),
        E('div', {id: subId || ('_sub_' + valueId), style: 'font-size:10px;color:#545d68;margin-top:2px'}, [''])
    ]);
}

return view.extend({

    load: function() {
        return Promise.all([
            callStatus(),
            callStats(),
            callGroups(),
            callWanIp(),
            callTproxyStatus()
        ]);
    },

    render: function(data) {
        var status  = data[0] || {};
        var stats   = data[1] || {};
        var groups  = data[2] || {};
        var wanData = data[3] || {};
        var tproxy  = data[4] || {};

        var setTxt = function(id, val) {
            var el = document.getElementById(id);
            if (el) el.textContent = val;
        };

        var node = E('div', {style: 'font-family:inherit'}, [

            /* Hero карточка */
            E('div', {
                style: 'display:flex;align-items:center;gap:16px;padding:16px 18px;'
                     + 'background:linear-gradient(135deg,#0d1117,#161b22);'
                     + 'border:1px solid rgba(232,103,60,.25);border-radius:5px;margin-bottom:14px'
            }, [
                E('img', {
                    src: L.resource('4eburnet/logo.png'),
                    style: 'width:64px;height:64px;border-radius:9px;object-fit:cover;'
                         + 'box-shadow:0 4px 20px rgba(0,0,0,.5);flex-shrink:0'
                }),
                E('div', {style: 'flex:1'}, [
                    E('div', {style: 'font-size:20px;font-weight:700;color:#e6edf3'}, ['4eburNet']),
                    E('div', {style: 'font-size:11px;color:#8d96a0;margin-top:3px'},
                        ['Прокси-маршрутизатор · OpenWrt']),
                    E('div', {style: 'margin-top:8px;display:flex;gap:6px;flex-wrap:wrap'}, [
                        badge('v0.1.0', 'bnt'),
                        E('span', {
                            id: 'hero-status',
                            style: 'display:inline-block;padding:2px 8px;border-radius:3px;font-size:10px;font-weight:600;'
                                 + (status.running
                                     ? 'background:rgba(62,207,106,.12);color:#3ecf6a;border:1px solid rgba(62,207,106,.2)'
                                     : 'background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.2)')
                        }, [status.running ? '● Активен' : '● Остановлен']),
                        badge(status.mode || '—', 'bin'),
                        badge('VLESS · AWG · DoQ', 'bpu')
                    ])
                ]),
                E('div', {style: 'text-align:right;flex-shrink:0'}, [
                    E('div', {
                        id: 'hero-uptime',
                        style: 'font-family:monospace;font-size:11px;color:#545d68'
                    }, [status.running ? 'Аптайм: ' + fmtUptime(status.uptime) : '—']),
                    E('div', {style: 'display:flex;gap:6px;margin-top:8px;justify-content:flex-end'}, [
                        E('button', {
                            class: 'btn cbi-button',
                            style: 'padding:4px 10px;font-size:11px',
                            click: function() {
                                callReload().then(function(r) {
                                    if (r && r.ok)
                                        ui.addNotification(null, E('p', {}, [_('Конфиг перечитан')]), 'info');
                                });
                            }
                        }, [_('↺ Конфиг')]),
                        E('button', {
                            class: 'btn cbi-button-negative',
                            style: 'padding:4px 10px;font-size:11px',
                            click: function() {
                                if (confirm(_('Остановить демон?')))
                                    callStop().then(function() { location.reload(); });
                            }
                        }, [_('⏹ Стоп')])
                    ])
                ])
            ]),

            /* Предупреждение об отсутствии kmod-nft-tproxy */
            !tproxy.available ? E('div', {
                style: 'background:rgba(240,180,41,.06);border:1px solid rgba(240,180,41,.3);'
                     + 'border-radius:5px;padding:10px 14px;margin-bottom:14px;'
                     + 'display:flex;align-items:center;gap:10px'
            }, [
                E('span', {style: 'font-size:16px'}, ['⚠']),
                E('div', {}, [
                    E('div', {style: 'font-weight:600;color:#f0b429;font-size:12px'},
                        [_('kmod-nft-tproxy недоступен')]),
                    E('div', {style: 'font-size:11px;color:#8d96a0;margin-top:3px'}, [
                        _('Перехват трафика отключён. Установите: '),
                        E('code', {style: 'background:#21262d;padding:1px 5px;border-radius:3px'}, ['opkg install kmod-nft-tproxy'])
                    ])
                ])
            ]) : E('span'),

            /* Статусные карточки */
            E('div', {
                style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));'
                     + 'gap:10px;margin-bottom:14px'
            }, [
                statusCard(_('Статус'), 'stat-status', 'stat-uptime', status.running ? 'ok' : ''),
                statusCard(_('Режим'), 'stat-mode', '_sub_stat-mode', ''),
                statusCard(_('Соединения'), 'stat-conns', 'stat-conns-s', ''),
                statusCard(_('DNS запросов'), 'stat-dns', 'stat-dns-s', ''),
                statusCard(_('Группы'), 'stat-groups', '_sub_stat-groups', 'ok')
            ]),

            /* Нижняя сетка: WAN IP + группы */
            E('div', {style: 'display:grid;grid-template-columns:1fr 1fr;gap:12px'}, [

                E('div', {
                    style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:14px'
                }, [
                    E('div', {style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:10px'}, [
                        E('div', {style: 'font-size:12px;font-weight:600;color:#8d96a0'}, [_('📡 Внешний IP')]),
                        E('button', {
                            class: 'btn cbi-button',
                            style: 'padding:3px 9px;font-size:11px',
                            click: function() {
                                callWanIp().then(function(d) {
                                    if (d && d.ip)
                                        document.getElementById('wan-ip-txt').textContent = d.ip;
                                });
                            }
                        }, ['⟳'])
                    ]),
                    E('div', {
                        id: 'wan-ip-txt',
                        style: 'font-family:monospace;font-size:18px;font-weight:700;color:#ff8c5a'
                    }, [wanData.ip || '—']),
                    E('div', {style: 'font-size:10px;color:#545d68;margin-top:2px'}, [_('WAN IP')])
                ]),

                E('div', {
                    style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:14px'
                }, [
                    E('div', {style: 'font-size:12px;font-weight:600;color:#8d96a0;margin-bottom:10px'}, [_('👥 Proxy группы')]),
                    E('div', {id: 'groups-mini'}, [
                        (groups.groups || []).length > 0
                        ? E('div', {},
                            (groups.groups || []).slice(0, 4).map(function(g) {
                                return E('div', {
                                    style: 'display:flex;align-items:center;gap:8px;'
                                         + 'padding:5px 8px;background:rgba(255,255,255,.03);'
                                         + 'border-radius:4px;margin-bottom:4px'
                                }, [
                                    E('div', {
                                        style: 'width:7px;height:7px;border-radius:50%;flex-shrink:0;'
                                             + 'background:' + (g.available ? '#3ecf6a' : '#f85149')
                                    }),
                                    E('div', {style: 'flex:1;font-size:11px;font-weight:600;color:#e6edf3'}, [g.name || '—']),
                                    E('div', {
                                        style: 'font-family:monospace;font-size:10px;'
                                             + 'color:' + ((g.latency_ms || 0) < 100 ? '#3ecf6a' : '#f0b429')
                                    }, [g.latency_ms ? g.latency_ms + 'мс' : '—'])
                                ]);
                            }))
                        : E('div', {style: 'font-size:11px;color:#545d68'}, [_('Нет данных от демона')])
                    ])
                ])
            ])
        ]);

        /* Заполнить stat cards */
        setTxt('stat-status', status.running ? _('Активен') : _('Остановлен'));
        setTxt('stat-uptime', status.running ? fmtUptime(status.uptime) : '');
        setTxt('stat-mode', status.mode || '—');
        setTxt('stat-conns', String(stats.connections || '—'));
        setTxt('stat-conns-s', _('Всего: ') + (stats.connections_total || 0));
        setTxt('stat-dns', String(stats.dns_queries || '—'));
        setTxt('stat-dns-s', _('Кэш: ') + (stats.dns_cached || 0));
        setTxt('stat-groups', String((groups.groups || []).length || '—'));

        /* Polling: статус каждые 3 сек */
        poll.add(function() {
            return callStatus().then(function(d) {
                if (!d) return;
                var hs = document.getElementById('hero-status');
                if (hs) {
                    hs.textContent = d.running ? '● Активен' : '● Остановлен';
                    hs.style.color = d.running ? '#3ecf6a' : '#f85149';
                }
                setTxt('hero-uptime', d.running ? 'Аптайм: ' + fmtUptime(d.uptime) : '—');
                setTxt('stat-status', d.running ? _('Активен') : _('Остановлен'));
                setTxt('stat-uptime', d.running ? fmtUptime(d.uptime) : '');
            });
        }, 3);

        return node;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
