'use strict';
'require view';
'require rpc';

var callServerList   = rpc.declare({ object: '4eburnet', method: 'server_list' });
var callServerAdd    = rpc.declare({
    object: '4eburnet', method: 'server_add',
    params: ['name', 'protocol', 'address', 'port',
             'transport', 'uuid', 'password',
             'reality_pbk', 'reality_sid',
             'hy2_obfs_password', 'hy2_sni', 'hy2_insecure',
             'hy2_up_mbps', 'hy2_down_mbps']
});
var callServerDelete = rpc.declare({
    object: '4eburnet', method: 'server_delete',
    params: ['section']
});

var TH = 'padding:7px 10px;font-size:10px;color:#545d68;'
       + 'text-transform:uppercase;letter-spacing:.05em;'
       + 'border-bottom:1px solid #30363d;text-align:left';
var TD = 'padding:7px 10px;border-bottom:1px solid #21262d;font-size:11px';

var PROTO_COLORS = {
    vless: '#bc8cff', trojan: '#4aa8f0',
    shadowsocks: '#f0b429', awg: '#3ecf6a', hysteria2: '#ff7b54'
};

function mkInp(id, placeholder, mono) {
    return E('input', {
        id: id, type: 'text', placeholder: placeholder || '',
        style: 'width:100%;padding:5px 8px;background:#21262d;'
             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
             + 'font-size:11px;outline:none;box-sizing:border-box;'
             + (mono ? 'font-family:monospace' : '')
    });
}

function gv(id) {
    var el = document.getElementById(id);
    return el ? el.value.trim() : '';
}

return view.extend({

    load: function() {
        return callServerList();
    },

    render: function(data) {
        var servers = (data || {}).servers || [];

        var statusEl = E('div', {
            style: 'font-size:11px;min-height:16px;margin-top:8px'
        }, ['']);

        function showStatus(msg, ok) {
            statusEl.textContent = msg;
            statusEl.style.color = ok ? '#3ecf6a' : '#f85149';
        }

        function rebuildList() {
            return callServerList().then(function(r) {
                servers = (r || {}).servers || [];
                var tbody = document.getElementById('srv-tbody');
                if (!tbody) return;
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                buildRows(servers, tbody);
            });
        }

        function buildRows(list, tbody) {
            if (list.length === 0) {
                var empty = document.createElement('tr');
                var td = document.createElement('td');
                td.colSpan = 5;
                td.style = 'padding:24px;text-align:center;color:#545d68;font-size:11px';
                td.textContent = _('Серверы не настроены. Добавьте сервер ниже.');
                empty.appendChild(td);
                tbody.appendChild(empty);
                return;
            }
            list.forEach(function(s) {
                var proto = s.protocol || '—';
                var pcol  = PROTO_COLORS[proto] || '#8d96a0';
                var row = E('tr', {}, [
                    E('td', {style: TD + ';font-weight:600;color:#e6edf3'}, [s.name || '—']),
                    E('td', {style: TD}, [
                        E('span', {
                            style: 'padding:2px 6px;border-radius:3px;font-size:10px;font-weight:600;'
                                 + 'background:rgba(255,255,255,.06);color:' + pcol
                        }, [proto.toUpperCase()])
                    ]),
                    E('td', {style: TD + ';font-family:monospace;color:#4aa8f0'}, [
                        (s.address || '—') + ':' + (s.port || '—')
                    ]),
                    E('td', {style: TD + ';color:#8d96a0'}, [
                        s.protocol === 'hysteria2'
                            ? (s.hy2_obfs_password ? 'salamander' : 'quic')
                            : (s.transport || 'tcp')
                    ]),
                    E('td', {style: TD}, [
                        s['.name'] ? E('button', {
                            class: 'btn cbi-button-negative',
                            style: 'padding:2px 8px;font-size:10px',
                            click: function() {
                                if (!confirm(_('Удалить сервер ') + (s.name || '') + '?')) return;
                                callServerDelete(s['.name']).then(function(res) {
                                    if (res && res.ok) {
                                        showStatus('✓ ' + _('Удалён'), true);
                                        rebuildList();
                                    } else {
                                        showStatus('✕ ' + ((res && res.error) || _('ошибка')), false);
                                    }
                                });
                            }
                        }, ['✕']) : E('span')
                    ])
                ]);
                tbody.appendChild(row);
            });
        }

        var tbody = E('tbody', {id: 'srv-tbody'}, []);
        buildRows(servers, tbody);

        /* Показать/скрыть поля в зависимости от протокола */
        var protoSel = E('select', {
            id: 'add-proto',
            style: 'padding:5px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px',
            change: function() { updateFields(); }
        }, [
            E('option', {value: 'vless'},       ['VLESS']),
            E('option', {value: 'trojan'},       ['Trojan']),
            E('option', {value: 'shadowsocks'},  ['Shadowsocks']),
            E('option', {value: 'awg'},          ['AmneziaWG']),
            E('option', {value: 'hysteria2'},    ['Hysteria2'])
        ]);

        var transportSel = E('select', {
            id: 'add-transport',
            style: 'padding:5px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px'
        }, [
            E('option', {value: 'tcp'},     ['TCP']),
            E('option', {value: 'reality'}, ['XTLS-Reality']),
            E('option', {value: 'xhttp'},   ['XHTTP'])
        ]);

        /* Строки с опциональными полями */
        var rowUuid     = E('div', {id: 'row-uuid',     style: ''}, [mkInp('add-uuid',     'UUID / пароль', true)]);
        var rowPassword = E('div', {id: 'row-password', style: 'display:none'}, [mkInp('add-password', 'Пароль', true)]);
        var rowReality  = E('div', {id: 'row-reality',  style: 'display:none'}, [
            E('div', {style: 'display:grid;grid-template-columns:1fr 1fr;gap:8px'}, [
                mkInp('add-pbk',  'Reality Public Key', true),
                mkInp('add-sid',  'Short ID',           true)
            ])
        ]);

        /* Hysteria2-специфичные поля */
        var rowHy2Auth = E('div', {id: 'row-hy2-auth', style: 'display:none'}, [
            mkInp('add-hy2-password', 'Пароль авторизации', true)
        ]);
        var rowHy2Obfs = E('div', {id: 'row-hy2-obfs', style: 'display:none'}, [
            mkInp('add-hy2-obfs-password',
                  'Salamander obfs пароль (пусто = без obfs)', true)
        ]);
        var rowHy2Sni = E('div', {id: 'row-hy2-sni', style: 'display:none'}, [
            mkInp('add-hy2-sni', 'SNI (пусто = server address)', false)
        ]);
        var rowHy2Insecure = E('div', {id: 'row-hy2-insecure', style: 'display:none'}, [
            E('label', {
                style: 'display:flex;align-items:center;gap:6px;'
                     + 'font-size:11px;color:#e6edf3;cursor:pointer'
            }, [
                E('input', {type: 'checkbox', id: 'add-hy2-insecure'}),
                _('Пропустить проверку TLS сертификата')
            ])
        ]);
        var rowHy2Bw = E('div', {id: 'row-hy2-bw', style: 'display:none'}, [
            E('div', {style: 'display:grid;grid-template-columns:1fr 1fr;gap:8px'}, [
                mkInp('add-hy2-up',   '↑ Up Мбит/с (0=авто)',   false),
                mkInp('add-hy2-down', '↓ Down Мбит/с (0=авто)', false)
            ])
        ]);

        function updateFields() {
            var p = protoSel.value;
            var t = transportSel.value;
            var isHy2 = (p === 'hysteria2');

            /* UUID / пароль */
            document.getElementById('row-uuid').style.display
                = (p === 'vless' || p === 'trojan') ? '' : 'none';
            document.getElementById('row-password').style.display
                = (p === 'shadowsocks') ? '' : 'none';
            /* Reality поля — только для VLESS + reality */
            document.getElementById('row-reality').style.display
                = (p === 'vless' && t === 'reality') ? '' : 'none';

            /* Hysteria2 поля */
            ['row-hy2-auth', 'row-hy2-obfs', 'row-hy2-sni',
             'row-hy2-insecure', 'row-hy2-bw'].forEach(function(id) {
                var el = document.getElementById(id);
                if (el) el.style.display = isHy2 ? '' : 'none';
            });
            var hy2Wrap = document.getElementById('hy2-wrap');
            if (hy2Wrap) hy2Wrap.style.display = isHy2 ? '' : 'none';

            /* Скрыть transport для Hysteria2 — QUIC, выбор не нужен */
            var transportRow = document.getElementById('row-transport');
            if (transportRow) transportRow.style.display = isHy2 ? 'none' : '';
        }

        transportSel.addEventListener('change', function() { updateFields(); });

        return E('div', {}, [
            E('div', {
                style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px'
            }, [
                E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3'},
                    [_('Серверы')]),
                E('span', {style: 'font-size:11px;color:#545d68'},
                    [String(servers.length) + ' ' + _('серверов')])
            ]),

            E('div', {
                style: 'overflow-x:auto;background:#161b22;border:1px solid #30363d;'
                     + 'border-radius:5px;margin-bottom:14px'
            }, [
                E('table', {style: 'width:100%;border-collapse:collapse'}, [
                    E('thead', {}, [E('tr', {}, [
                        E('th', {style: TH}, [_('Имя')]),
                        E('th', {style: TH}, [_('Протокол')]),
                        E('th', {style: TH}, [_('Адрес:Порт')]),
                        E('th', {style: TH}, [_('Транспорт')]),
                        E('th', {style: TH}, [''])
                    ])]),
                    tbody
                ])
            ]),

            /* Форма добавления */
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:14px'
            }, [
                E('div', {
                    style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                         + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:12px'
                }, [_('Добавить сервер')]),

                E('div', {style: 'display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px'}, [
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Имя')]),
                        mkInp('add-name', 'my-server', false)
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Протокол')]),
                        protoSel
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Адрес (домен или IP)')]),
                        mkInp('add-address', 'example.com', true)
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Порт')]),
                        mkInp('add-port', '443', false)
                    ]),
                    E('div', {id: 'row-transport'}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Транспорт')]),
                        transportSel
                    ])
                ]),

                /* Опциональные поля */
                E('div', {style: 'margin-bottom:10px'}, [
                    E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('UUID / Пароль')]),
                    rowUuid,
                    rowPassword
                ]),
                E('div', {id: 'reality-wrap', style: 'margin-bottom:10px'}, [
                    E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Reality параметры')]),
                    rowReality
                ]),
                E('div', {id: 'hy2-wrap', style: 'display:none;margin-bottom:10px'}, [
                    E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Hysteria2 Auth пароль')]),
                    rowHy2Auth,
                    E('div', {style: 'font-size:10px;color:#545d68;margin:6px 0 3px'}, [_('Salamander obfuscation (опционально)')]),
                    rowHy2Obfs,
                    E('div', {style: 'font-size:10px;color:#545d68;margin:6px 0 3px'}, [_('SNI')]),
                    rowHy2Sni,
                    rowHy2Insecure,
                    E('div', {style: 'font-size:10px;color:#545d68;margin:6px 0 3px'}, [_('Bandwidth (Brutal CC)')]),
                    rowHy2Bw
                ]),

                E('div', {style: 'display:flex;gap:8px;align-items:center;flex-wrap:wrap'}, [
                    E('button', {
                        class: 'btn cbi-button',
                        click: function() {
                            var name  = gv('add-name');
                            var proto = protoSel.value;
                            var addr  = gv('add-address');
                            var port  = gv('add-port');

                            if (!name || !addr || !port) {
                                showStatus('✕ ' + _('Имя, адрес и порт обязательны'), false);
                                return;
                            }
                            if (proto === 'hysteria2' && !gv('add-hy2-password')) {
                                showStatus('✕ ' + _('Для Hysteria2 обязателен пароль'), false);
                                return;
                            }

                            var uuid     = gv('add-uuid');
                            var password = gv('add-password');
                            var pbk      = gv('add-pbk');
                            var sid      = gv('add-sid');
                            var transport = transportSel.value;

                            /* Hysteria2 параметры */
                            var hy2Pass  = gv('add-hy2-password');
                            var hy2Obfs  = gv('add-hy2-obfs-password');
                            var hy2Sni   = gv('add-hy2-sni');
                            var hy2InEl  = document.getElementById('add-hy2-insecure');
                            var hy2Insec = (hy2InEl && hy2InEl.checked) ? 1 : 0;
                            var hy2Up    = gv('add-hy2-up') || '0';
                            var hy2Down  = gv('add-hy2-down') || '0';

                            /* Hysteria2: auth пароль идёт в 'password' слот,
                             * uuid оставляем пустым */
                            var authUuid = (proto === 'hysteria2') ? '' : (uuid || password);
                            var authPwd  = (proto === 'hysteria2') ? hy2Pass : password;

                            showStatus(_('Добавление…'), true);

                            callServerAdd(
                                name, proto, addr, port,
                                transport, authUuid, authPwd,
                                pbk, sid,
                                hy2Obfs, hy2Sni, hy2Insec, hy2Up, hy2Down
                            ).then(function(r) {
                                if (r && r.ok) {
                                    showStatus('✓ ' + _('Сервер добавлен'), true);
                                    /* Очистить форму */
                                    ['add-name','add-address','add-port',
                                     'add-uuid','add-password','add-pbk','add-sid',
                                     'add-hy2-password','add-hy2-obfs-password',
                                     'add-hy2-sni','add-hy2-up','add-hy2-down'
                                    ].forEach(function(id) {
                                        var el = document.getElementById(id);
                                        if (el) el.value = '';
                                    });
                                    var hy2InEl2 = document.getElementById('add-hy2-insecure');
                                    if (hy2InEl2) hy2InEl2.checked = false;
                                    rebuildList();
                                } else {
                                    showStatus('✕ ' + ((r && r.error) || _('ошибка')), false);
                                }
                            });
                        }
                    }, [_('+ Добавить')]),
                    statusEl
                ])
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
