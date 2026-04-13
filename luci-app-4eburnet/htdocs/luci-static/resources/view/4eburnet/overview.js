'use strict';
'require view';
'require rpc';

var callStatus = rpc.declare({ object: '4eburnet', method: 'status' });
var callStats  = rpc.declare({ object: '4eburnet', method: 'stats' });
var callGroups = rpc.declare({ object: '4eburnet', method: 'groups' });
var callWanIp  = rpc.declare({ object: '4eburnet', method: 'wan_ip' });
var callTproxy = rpc.declare({ object: '4eburnet', method: 'tproxy_status' });
var callReload  = rpc.declare({ object: '4eburnet', method: 'reload' });
var callStop    = rpc.declare({ object: '4eburnet', method: 'stop' });
var callRestart = rpc.declare({ object: '4eburnet', method: 'restart' });

function fmtUptime(sec) {
    sec = sec || 0;
    return Math.floor(sec / 3600) + 'ч '
         + Math.floor(sec % 3600 / 60) + 'м '
         + (sec % 60) + 'с';
}

function badge(text, col) {
    return E('span', {
        style: 'display:inline-block;padding:2px 7px;border-radius:3px;'
             + 'font-size:10px;font-weight:600;margin-right:4px;'
             + 'background:rgba(255,255,255,.06);color:' + (col || '#8d96a0')
    }, [text]);
}

function statCard(label, valId, subId) {
    return E('div', {
        style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:12px 14px'
    }, [
        E('div', {style: 'font-size:10px;color:#545d68;text-transform:uppercase;letter-spacing:.05em'}, [label]),
        E('div', {id: valId, style: 'font-size:18px;font-weight:700;margin-top:4px;color:#e6edf3'}, ['—']),
        E('div', {id: subId, style: 'font-size:10px;color:#545d68;margin-top:2px'}, [''])
    ]);
}

function setTxt(id, val) {
    var el = document.getElementById(id);
    if (el) el.textContent = val;
}

return view.extend({

    load: function() {
        return Promise.all([
            callStatus(),
            callStats(),
            callGroups(),
            callWanIp(),
            callTproxy()
        ]);
    },

    render: function(data) {
        var status  = data[0] || {};
        var stats   = data[1] || {};
        var groups  = data[2] || {};
        var wanData = data[3] || {};
        var tproxy  = data[4] || {};

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
                        badge('v' + (status.version || '?'), '#8d96a0'),
                        E('span', {
                            id: 'hero-status',
                            style: 'display:inline-block;padding:2px 8px;border-radius:3px;'
                                 + 'font-size:10px;font-weight:600;'
                                 + (status.running
                                     ? 'background:rgba(62,207,106,.12);color:#3ecf6a;border:1px solid rgba(62,207,106,.2)'
                                     : 'background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.2)')
                        }, [status.running ? '● Активен' : '● Остановлен']),
                        badge(status.mode || '—', '#4aa8f0'),
                        badge('VLESS · AWG · DoQ', '#bc8cff')
                    ])
                ]),
                E('div', {style: 'text-align:right;flex-shrink:0'}, [
                    E('div', {
                        id: 'hero-uptime',
                        style: 'font-family:monospace;font-size:11px;color:#545d68'
                    }, [status.running ? 'Аптайм: ' + fmtUptime(status.uptime) : '—']),
                    E('div', {style: 'display:flex;gap:6px;margin-top:8px;justify-content:flex-end'},
                        status.running ? [
                            E('button', {
                                class: 'btn cbi-button',
                                style: 'padding:4px 10px;font-size:11px',
                                click: function() {
                                    callReload().then(function(r) {
                                        if (r && r.ok)
                                            ui.addNotification(null, E('p', {}, [_('Конфиг перечитан')]), 'info');
                                    }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                                }
                            }, [_('↺ Конфиг')]),
                            E('button', {
                                class: 'btn cbi-button-negative',
                                style: 'padding:4px 10px;font-size:11px',
                                click: function() {
                                    if (confirm(_('Остановить демон?')))
                                        callStop().then(function() { location.reload(); }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                                }
                            }, [_('⏹ Стоп')])
                        ] : [
                            E('button', {
                                class: 'btn cbi-button',
                                style: 'padding:4px 10px;font-size:11px;background:#238636;color:#fff;border-color:#238636',
                                click: function() {
                                    callRestart().then(function() { location.reload(); }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                                }
                            }, [_('▶ Старт')])
                        ]
                    )
                ])
            ]),

            /* Статус mark-based routing */
            (!tproxy.routing_ok || !tproxy.table_ok) ? E('div', {
                style: 'background:rgba(240,180,41,.06);border:1px solid rgba(240,180,41,.3);'
                     + 'border-radius:5px;padding:10px 14px;margin-bottom:14px;'
                     + 'display:flex;align-items:center;gap:10px'
            }, [
                E('span', {style: 'font-size:16px'}, ['⚠']),
                E('div', {}, [
                    E('div', {style: 'font-weight:600;color:#f0b429;font-size:12px'},
                        [_('Маршрутизация не настроена')]),
                    E('div', {style: 'font-size:11px;color:#8d96a0;margin-top:3px'}, [
                        _('ip rule fwmark 0x01 → table 100 не активен. Запустите 4eburNet.')
                    ])
                ])
            ]) : E('span'),

            /* Статусные карточки */
            E('div', {
                style: 'display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));'
                     + 'gap:10px;margin-bottom:14px'
            }, [
                statCard(_('Статус'),      'stat-status', 'stat-uptime'),
                statCard(_('Режим'),       'stat-mode',   'stat-mode-sub'),
                statCard(_('Соединения'),  'stat-conns',  'stat-conns-s'),
                statCard(_('DNS запросов'),'stat-dns',    'stat-dns-s'),
                statCard(_('Группы'),      'stat-groups', 'stat-groups-s')
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
                                        setTxt('wan-ip-txt', d.ip);
                                }).catch(function() {});
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
                    E('div', {style: 'font-size:12px;font-weight:600;color:#8d96a0;margin-bottom:10px'},
                        [_('👥 Proxy группы')]),
                    E('div', {id: 'groups-mini'}, [
                        (groups.groups || []).length > 0
                        ? E('div', {},
                            (groups.groups || []).slice(0, 4).map(function(g) {
                                /* B4-06: available/latency на уровне сервера, не группы */
                                var srvs = g.servers || [];
                                var avail = srvs.some(function(s) { return s.available; });
                                var sel = srvs[g.selected] || srvs[0] || {};
                                var lat = sel.latency || 0;
                                return E('div', {
                                    style: 'display:flex;align-items:center;gap:8px;'
                                         + 'padding:5px 8px;background:rgba(255,255,255,.03);'
                                         + 'border-radius:4px;margin-bottom:4px'
                                }, [
                                    E('div', {
                                        style: 'width:7px;height:7px;border-radius:50%;flex-shrink:0;'
                                             + 'background:' + (avail ? '#3ecf6a' : '#f85149')
                                    }),
                                    E('div', {style: 'flex:1;font-size:11px;font-weight:600;color:#e6edf3'}, [g.name || '—']),
                                    E('div', {
                                        style: 'font-family:monospace;font-size:10px;'
                                             + 'color:' + (lat < 100 ? '#3ecf6a' : '#f0b429')
                                    }, [lat ? lat + 'мс' : '—'])
                                ]);
                            }))
                        : E('div', {style: 'font-size:11px;color:#545d68'}, [_('Нет данных от демона')])
                    ])
                ])
            ])
        ]);

        /* Заполнить stat cards начальными данными */
        setTxt('stat-status', status.running ? _('Активен') : _('Остановлен'));
        setTxt('stat-uptime', status.running ? fmtUptime(status.uptime) : '');
        setTxt('stat-mode',   status.mode || '—');
        setTxt('stat-conns',  String(stats.connections_active || 0));
        setTxt('stat-conns-s', _('Всего: ') + (stats.connections_total || 0));
        setTxt('stat-dns',    String(stats.dns_queries || 0));
        setTxt('stat-dns-s',  _('Кэш: ') + (stats.dns_cached || 0));
        setTxt('stat-groups', String((groups.groups || []).length || '—'));

        /* Polling через setInterval с cleanup при уходе со страницы.
           clearInterval вызывается в handleReset — LuCI дёргает его при
           переходе на другую страницу, так что таймеры не накапливаются. */
        var pollTimer = setInterval(function() {
            callStatus().then(function(d) {
                if (!d) return;
                /* Если DOM ушёл — остановить таймер */
                var hs = document.getElementById('hero-status');
                if (!hs) { clearInterval(pollTimer); return; }
                hs.textContent = d.running ? '● Активен' : '● Остановлен';
                hs.style.cssText = 'display:inline-block;padding:2px 8px;border-radius:3px;'
                    + 'font-size:10px;font-weight:600;'
                    + (d.running
                        ? 'background:rgba(62,207,106,.12);color:#3ecf6a;border:1px solid rgba(62,207,106,.2)'
                        : 'background:rgba(248,81,73,.12);color:#f85149;border:1px solid rgba(248,81,73,.2)');
                setTxt('hero-uptime', d.running ? 'Аптайм: ' + fmtUptime(d.uptime) : '—');
                setTxt('stat-status', d.running ? _('Активен') : _('Остановлен'));
                setTxt('stat-uptime', d.running ? fmtUptime(d.uptime) : '');
            }).catch(function() {});
        }, 3000);

        /* Сохранить ID таймера в dataset для handleReset */
        node.dataset.pollTimer = String(pollTimer);
        return node;
    },

    handleSaveApply: null,
    handleSave: null,

    handleReset: function() {
        /* Остановить polling при уходе со страницы */
        var node = document.querySelector('[data-poll-timer]');
        if (node && node.dataset.pollTimer) {
            clearInterval(parseInt(node.dataset.pollTimer, 10));
            delete node.dataset.pollTimer;
        }
    }
});
