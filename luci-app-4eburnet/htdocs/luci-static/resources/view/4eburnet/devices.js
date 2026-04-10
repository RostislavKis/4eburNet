'use strict';
'require view';
'require rpc';

var callDevices = rpc.declare({ object: '4eburnet', method: 'devices' });

var TH_STYLE = 'padding:7px 10px;font-size:10px;color:#545d68;'
    + 'text-transform:uppercase;letter-spacing:.05em;'
    + 'border-bottom:1px solid #30363d;text-align:left';

var TD_STYLE = 'padding:6px 10px;border-bottom:1px solid #21262d';

return view.extend({

    load: function() {
        return callDevices();
    },

    render: function(data) {
        var devs = (data || {}).devices || [];

        var rows = devs.length > 0
            ? devs.map(function(d) {
                return E('tr', {}, [
                    E('td', {style: TD_STYLE}, [
                        E('div', {
                            style: 'width:7px;height:7px;border-radius:50%;'
                                 + 'background:#3ecf6a;display:inline-block'
                        })
                    ]),
                    E('td', {style: TD_STYLE + ';font-family:monospace;font-size:11px'}, [d.mac]),
                    E('td', {style: TD_STYLE + ';font-family:monospace;font-size:11px'}, [d.ip]),
                    E('td', {style: TD_STYLE + ';font-size:11px;color:#8d96a0'}, [d.iface || '—']),
                    E('td', {style: TD_STYLE}, [
                        E('select', {
                            style: 'padding:3px 7px;background:#21262d;border:1px solid #30363d;'
                                 + 'border-radius:4px;color:#e6edf3;font-size:11px'
                        }, [
                            E('option', {value: 'default'}, [_('default')]),
                            E('option', {value: 'proxy'},   [_('proxy')]),
                            E('option', {value: 'bypass'},  [_('bypass')]),
                            E('option', {value: 'block'},   [_('block')])
                        ])
                    ])
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
                style: 'display:flex;align-items:center;'
                     + 'justify-content:space-between;margin-bottom:12px'
            }, [
                E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3'}, [
                    _('Устройства в сети'),
                    E('span', {style: 'font-size:11px;color:#545d68;font-weight:400;margin-left:8px'}, [
                        '(' + devs.length + ')'
                    ])
                ]),
                E('button', {
                    class: 'btn cbi-button',
                    click: function() { location.reload(); }
                }, [_('📡 Обновить')])
            ]),
            E('div', {
                style: 'overflow-x:auto;background:#161b22;'
                     + 'border:1px solid #30363d;border-radius:5px'
            }, [
                E('table', {style: 'width:100%;border-collapse:collapse'}, [
                    E('thead', {}, [
                        E('tr', {}, [
                            E('th', {style: TH_STYLE}, ['']),
                            E('th', {style: TH_STYLE}, ['MAC']),
                            E('th', {style: TH_STYLE}, ['IP']),
                            E('th', {style: TH_STYLE}, [_('Интерфейс')]),
                            E('th', {style: TH_STYLE}, [_('Политика')])
                        ])
                    ]),
                    E('tbody', {}, rows)
                ])
            ]),
            E('div', {style: 'font-size:10px;color:#545d68;margin-top:8px'}, [
                _('Источник: /proc/net/arp · Политика применяется через MAC-based routing')
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
