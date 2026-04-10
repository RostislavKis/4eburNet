'use strict';
'require view';
'require rpc';

var callRulesList  = rpc.declare({ object: '4eburnet', method: 'rules_list' });
var callRuleAdd    = rpc.declare({
    object: '4eburnet', method: 'rule_add',
    params: ['type', 'value', 'target', 'priority']
});
var callRuleDelete = rpc.declare({
    object: '4eburnet', method: 'rule_delete',
    params: ['section']
});

var TH = 'padding:7px 10px;font-size:10px;color:#545d68;'
       + 'text-transform:uppercase;letter-spacing:.05em;'
       + 'border-bottom:1px solid #30363d;text-align:left';
var TD = 'padding:6px 10px;border-bottom:1px solid #21262d;font-size:11px';

var TARGET_COLORS = {
    'DIRECT':     '#3ecf6a',
    'MAIN-PROXY': '#4aa8f0',
    'REJECT':     '#f85149',
    'BLOCK':      '#f85149'
};

return view.extend({

    load: function() {
        return callRulesList();
    },

    render: function(data) {
        var rules = (data || {}).rules || [];
        var self  = this;

        var statusEl = E('div', {
            style: 'font-size:11px;min-height:16px;margin-top:6px'
        }, ['']);

        function showStatus(msg, ok) {
            statusEl.textContent = msg;
            statusEl.style.color = ok ? '#3ecf6a' : '#f85149';
        }

        /* Перерисовать таблицу */
        function rebuildTable() {
            return callRulesList().then(function(r) {
                rules = (r || {}).rules || [];
                var tbody = document.getElementById('rules-tbody');
                if (!tbody) return;
                while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
                buildRows(rules, tbody);
            });
        }

        function buildRows(ruleList, tbody) {
            if (ruleList.length === 0) {
                var empty = document.createElement('tr');
                var td = document.createElement('td');
                td.colSpan = 5;
                td.style = 'padding:20px;text-align:center;color:#545d68;font-size:11px';
                td.textContent = _('Правила не заданы');
                empty.appendChild(td);
                tbody.appendChild(empty);
                return;
            }
            ruleList.forEach(function(r) {
                var tcol = TARGET_COLORS[r.target] || '#e6edf3';
                var row = E('tr', {}, [
                    E('td', {style: TD + ';color:#545d68;font-family:monospace'},
                        [String(r.priority || '—')]),
                    E('td', {style: TD + ';color:#8d96a0'}, [r.type || '—']),
                    E('td', {style: TD + ';font-family:monospace;color:#4aa8f0'},
                        [r.value || '—']),
                    E('td', {style: TD + ';color:' + tcol + ';font-weight:600'},
                        [r.target || '—']),
                    E('td', {style: TD}, [
                        r['.name'] ? E('button', {
                            class: 'btn cbi-button-negative',
                            style: 'padding:2px 8px;font-size:10px',
                            click: function() {
                                if (!confirm(_('Удалить правило?'))) return;
                                callRuleDelete(r['.name']).then(function(res) {
                                    if (res && res.ok) {
                                        showStatus('✓ ' + _('Правило удалено'), true);
                                        rebuildTable();
                                    } else {
                                        showStatus('✕ ' + ((res && res.error) || _('ошибка')), false);
                                    }
                                });
                            }
                        }, ['✕']) : E('span', {style: 'color:#30363d'}, ['—'])
                    ])
                ]);
                tbody.appendChild(row);
            });
        }

        var tbody = E('tbody', {id: 'rules-tbody'}, []);
        buildRows(rules, tbody);

        /* Форма добавления */
        var typeSelect = E('select', {
            style: 'padding:5px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px'
        }, [
            E('option', {value: 'domain'},         ['domain']),
            E('option', {value: 'domain_suffix'},  ['domain_suffix']),
            E('option', {value: 'domain_keyword'}, ['domain_keyword']),
            E('option', {value: 'ip_cidr'},        ['ip_cidr']),
            E('option', {value: 'geoip'},          ['geoip']),
            E('option', {value: 'geosite'},        ['geosite']),
            E('option', {value: 'match'},          ['match (всё)'])
        ]);

        var valueInp = E('input', {
            type: 'text', placeholder: _('Значение (домен, IP, код страны…)'),
            style: 'padding:5px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px;width:220px;'
                 + 'font-family:monospace'
        });

        var targetInp = E('input', {
            type: 'text', placeholder: 'DIRECT / MAIN-PROXY',
            value: 'DIRECT',
            style: 'padding:5px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px;width:130px;'
                 + 'font-family:monospace'
        });

        var prioInp = E('input', {
            type: 'number', placeholder: '500', value: '500',
            style: 'padding:5px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px;width:70px'
        });

        return E('div', {}, [
            E('div', {
                style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px'
            }, [
                E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3'},
                    [_('Правила маршрутизации')]),
                E('span', {style: 'font-size:11px;color:#545d68'},
                    [String(rules.length) + ' ' + _('правил')])
            ]),

            E('div', {
                style: 'overflow-x:auto;background:#161b22;border:1px solid #30363d;border-radius:5px;margin-bottom:14px'
            }, [
                E('table', {style: 'width:100%;border-collapse:collapse'}, [
                    E('thead', {}, [E('tr', {}, [
                        E('th', {style: TH}, [_('Приоритет')]),
                        E('th', {style: TH}, [_('Тип')]),
                        E('th', {style: TH}, [_('Значение')]),
                        E('th', {style: TH}, [_('Цель')]),
                        E('th', {style: TH}, [''])
                    ])]),
                    tbody
                ])
            ]),

            /* Форма добавления правила */
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:14px'
            }, [
                E('div', {
                    style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                         + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:10px'
                }, [_('Добавить правило')]),
                E('div', {
                    style: 'display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end'
                }, [
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Тип')]),
                        typeSelect
                    ]),
                    E('div', {style: 'flex:1;min-width:180px'}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Значение')]),
                        valueInp
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Цель')]),
                        targetInp
                    ]),
                    E('div', {}, [
                        E('div', {style: 'font-size:10px;color:#545d68;margin-bottom:3px'}, [_('Приоритет')]),
                        prioInp
                    ]),
                    E('button', {
                        class: 'btn cbi-button',
                        style: 'margin-bottom:1px',
                        click: function() {
                            var rtype  = typeSelect.value;
                            var rvalue = valueInp.value.trim();
                            var target = targetInp.value.trim() || 'DIRECT';
                            var prio   = parseInt(prioInp.value, 10) || 500;

                            if (!rvalue && rtype !== 'match') {
                                showStatus('✕ ' + _('Введите значение'), false);
                                return;
                            }
                            showStatus(_('Добавление…'), true);

                            callRuleAdd(rtype, rvalue, target, prio).then(function(r) {
                                if (r && r.ok) {
                                    showStatus('✓ ' + _('Правило добавлено'), true);
                                    valueInp.value = '';
                                    rebuildTable();
                                } else {
                                    showStatus('✕ ' + ((r && r.error) || _('ошибка')), false);
                                }
                            });
                        }
                    }, [_('+ Добавить')])
                ]),
                statusEl
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
