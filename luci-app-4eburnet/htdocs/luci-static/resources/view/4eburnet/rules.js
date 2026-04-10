'use strict';
'require view';
'require uci';

return view.extend({

    load: function() {
        return uci.load('4eburnet');
    },

    render: function() {
        var rules = [];
        uci.sections('4eburnet', 'traffic_rule', function(s) {
            rules.push(s);
        });

        var rows = rules.length > 0
            ? rules.map(function(r, i) {
                return E('tr', {}, [
                    E('td', {style: 'padding:6px 10px;font-size:11px;color:#545d68'}, [String(r.priority || i)]),
                    E('td', {style: 'padding:6px 10px;font-size:11px;font-family:monospace'}, [r.type || '—']),
                    E('td', {style: 'padding:6px 10px;font-size:11px;font-family:monospace;color:#4aa8f0'}, [r.value || '—']),
                    E('td', {style: 'padding:6px 10px;font-size:11px;color:#3ecf6a'}, [r.target || '—'])
                ]);
            })
            : [E('tr', {}, [
                E('td', {
                    colspan: '4',
                    style: 'padding:20px;text-align:center;color:#545d68;font-size:11px'
                }, [_('Правила не заданы в /etc/config/4eburnet')])
            ])];

        return E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:12px'}, [_('Правила маршрутизации')]),
            E('div', {style: 'overflow-x:auto;background:#161b22;border:1px solid #30363d;border-radius:5px'}, [
                E('table', {style: 'width:100%;border-collapse:collapse'}, [
                    E('thead', {}, [E('tr', {}, [
                        E('th', {style: 'padding:7px 10px;font-size:10px;color:#545d68;text-align:left;border-bottom:1px solid #30363d'}, [_('Приоритет')]),
                        E('th', {style: 'padding:7px 10px;font-size:10px;color:#545d68;text-align:left;border-bottom:1px solid #30363d'}, [_('Тип')]),
                        E('th', {style: 'padding:7px 10px;font-size:10px;color:#545d68;text-align:left;border-bottom:1px solid #30363d'}, [_('Значение')]),
                        E('th', {style: 'padding:7px 10px;font-size:10px;color:#545d68;text-align:left;border-bottom:1px solid #30363d'}, [_('Цель')])
                    ])]),
                    E('tbody', {}, rows)
                ])
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
