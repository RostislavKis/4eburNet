'use strict';
'require view';
'require rpc';
'require ui';

var callDevices    = rpc.declare({ object: '4eburnet', method: 'devices' });
var callDeviceSave = rpc.declare({
    object: '4eburnet', method: 'device_save',
    params: ['mac', 'policy', 'group', 'alias']
});

var TH = 'padding:7px 10px;font-size:10px;color:#545d68;'
       + 'text-transform:uppercase;letter-spacing:.05em;'
       + 'border-bottom:1px solid #30363d;text-align:left';
var TD = 'padding:6px 10px;border-bottom:1px solid #21262d';

function policySelect(dev) {
    var sel = E('select', {
        style: 'padding:3px 7px;background:#21262d;border:1px solid #30363d;'
             + 'border-radius:4px;color:#e6edf3;font-size:11px;cursor:pointer'
    }, [
        E('option', {value: 'default'}, [_('default')]),
        E('option', {value: 'proxy'},   [_('proxy')]),
        E('option', {value: 'bypass'},  [_('bypass')]),
        E('option', {value: 'block'},   [_('block')])
    ]);

    /* Установить текущее значение */
    sel.value = dev.policy || 'default';

    var statusSpan = E('span', {
        style: 'font-size:10px;margin-left:6px;min-width:14px;display:inline-block'
    }, ['']);

    sel.addEventListener('change', function() {
        var chosen = sel.value;
        statusSpan.textContent = '…';
        statusSpan.style.color = '#8d96a0';
        callDeviceSave(dev.mac, chosen, dev.group || '', dev.alias || '')
            .then(function(r) {
                if (r && r.ok) {
                    dev.policy = chosen;
                    statusSpan.textContent = '✓';
                    statusSpan.style.color = '#3ecf6a';
                    /* Убрать галочку через 1.5 сек */
                    setTimeout(function() { statusSpan.textContent = ''; }, 1500);
                } else {
                    statusSpan.textContent = '✕';
                    statusSpan.style.color = '#f85149';
                    /* Откатить выбор */
                    sel.value = dev.policy || 'default';
                }
            }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
    });

    return E('div', {style: 'display:flex;align-items:center'}, [sel, statusSpan]);
}

return view.extend({

    load: function() {
        return callDevices();
    },

    render: function(data) {
        var devs = (data || {}).devices || [];

        var rows = devs.length > 0
            ? devs.map(function(d) {
                var dotColor = d.policy === 'block'  ? '#f85149'
                             : d.policy === 'bypass' ? '#f0b429'
                             : d.policy === 'proxy'  ? '#4aa8f0'
                             : '#3ecf6a';
                return E('tr', {}, [
                    E('td', {style: TD}, [
                        E('div', {
                            style: 'width:7px;height:7px;border-radius:50%;'
                                 + 'background:' + dotColor + ';display:inline-block'
                        })
                    ]),
                    E('td', {style: TD + ';font-family:monospace;font-size:11px'}, [d.mac]),
                    E('td', {style: TD + ';font-family:monospace;font-size:11px'}, [d.ip]),
                    E('td', {style: TD + ';font-size:11px;color:#8d96a0'}, [
                        d.hostname
                            ? E('span', {}, [
                                d.hostname,
                                E('span', {style: 'color:#30363d;margin-left:4px'}, [d.iface || ''])
                              ])
                            : (d.iface || '—')
                    ]),
                    E('td', {style: TD}, [policySelect(d)])
                ]);
            })
            : [E('tr', {}, [
                E('td', {
                    colspan: '5',
                    style: 'padding:20px;text-align:center;color:#545d68;font-size:11px'
                }, [_('Нет устройств в ARP таблице')])
            ])];

        return E('div', {}, [
            E('div', {
                style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px'
            }, [
                E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3'}, [
                    _('Устройства в сети'),
                    E('span', {style: 'font-size:11px;color:#545d68;font-weight:400;margin-left:8px'}, [
                        '(' + devs.length + ')'
                    ])
                ]),
                E('button', {
                    class: 'btn cbi-button',
                    click: function() {
                        callDevices().then(function(r) {
                            if (r) location.reload();
                        }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                    }
                }, [_('📡 Обновить')])
            ]),
            E('div', {
                style: 'overflow-x:auto;background:#161b22;border:1px solid #30363d;border-radius:5px'
            }, [
                E('table', {style: 'width:100%;border-collapse:collapse'}, [
                    E('thead', {}, [
                        E('tr', {}, [
                            E('th', {style: TH}, ['']),
                            E('th', {style: TH}, ['MAC']),
                            E('th', {style: TH}, ['IP']),
                            E('th', {style: TH}, [_('Хост / Интерфейс')]),
                            E('th', {style: TH}, [_('Политика')])
                        ])
                    ]),
                    E('tbody', {}, rows)
                ])
            ]),
            E('div', {style: 'font-size:10px;color:#545d68;margin-top:8px'}, [
                _('Источник: ARP + DHCP leases · Политика сохраняется в UCI и применяется через reload')
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
