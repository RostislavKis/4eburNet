'use strict';
'require view';
'require rpc';

var callGroups = rpc.declare({ object: '4eburnet', method: 'groups' });

return view.extend({

    load: function() {
        return callGroups();
    },

    render: function(data) {
        var groups = (data || {}).groups || [];

        var cards = groups.length > 0
            ? groups.map(function(g) {
                return E('div', {
                    style: 'background:#161b22;border:1px solid '
                         + (g.available ? 'rgba(62,207,106,.25)' : '#30363d')
                         + ';border-radius:5px;padding:12px 14px;margin-bottom:8px'
                }, [
                    E('div', {style: 'display:flex;align-items:center;gap:8px;margin-bottom:6px'}, [
                        E('div', {
                            style: 'width:8px;height:8px;border-radius:50%;'
                                 + 'background:' + (g.available ? '#3ecf6a' : '#f85149')
                        }),
                        E('div', {style: 'font-size:13px;font-weight:600;color:#e6edf3'}, [g.name || '—']),
                        E('div', {style: 'margin-left:auto;font-size:10px;color:#545d68'}, [g.type || ''])
                    ]),
                    E('div', {style: 'font-size:11px;color:#8d96a0'}, [
                        _('Задержка: '),
                        E('span', {
                            style: 'font-family:monospace;color:' + ((g.latency_ms || 0) < 100 ? '#3ecf6a' : '#f0b429')
                        }, [g.latency_ms ? g.latency_ms + ' мс' : '—'])
                    ])
                ]);
            })
            : [E('div', {style: 'font-size:11px;color:#545d68;padding:20px;text-align:center'}, [
                _('Нет данных от демона. Убедитесь что 4eburnetd запущен.')
            ])];

        return E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:12px'}, [
                _('Proxy группы')
            ]),
            E('div', {}, cards)
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
