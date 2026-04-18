'use strict';
'require view';
'require rpc';

var callStatus = rpc.declare({
    object: 'luci.4eburnet',
    method: 'status',
    expect: {}
});

function fmt_uptime(sec) {
    sec = sec || 0;
    var h = Math.floor(sec / 3600);
    var m = Math.floor((sec % 3600) / 60);
    if (h > 0) return h + 'ч ' + (m < 10 ? '0' : '') + m + 'м';
    return m + 'м';
}

return view.extend({
    load: function() {
        return callStatus();
    },

    render: function(data) {
        var st     = data.status  || 'stopped';
        var ver    = data.version || '—';
        var mode   = data.mode    || '—';
        var prof   = data.profile || '—';
        var uptime = data.uptime  || 0;

        var dot_color = st === 'running' ? '#22c55e'
                      : st === 'error'   ? '#f59e0b'
                      : '#ef4444';
        var st_label  = st === 'running' ? 'Активен'
                      : st === 'error'   ? 'Ошибка'
                      : 'Остановлен';

        var card_style = 'background:#fff;border:1px solid #e5e7eb;border-radius:12px;'
                       + 'padding:20px 24px;margin-bottom:12px;';
        var label_style = 'color:#6b7280;font-size:13px;min-width:80px;display:inline-block;';
        var value_style = 'color:#111827;font-size:14px;font-weight:500;';

        return E('div', { style: 'max-width:480px;margin:24px auto;font-family:system-ui,sans-serif;' }, [

            /* ── Шапка: лого + название + версия ── */
            E('div', { style: card_style + 'display:flex;align-items:center;gap:16px;' }, [
                E('img', {
                    src: '/luci-static/resources/4eburnet/logo.png',
                    style: 'width:48px;height:48px;border-radius:10px;flex-shrink:0;',
                    onerror: "this.style.display='none';this.nextElementSibling.style.display='flex';"
                }),
                E('div', {
                    style: 'display:none;width:48px;height:48px;border-radius:10px;'
                         + 'background:linear-gradient(135deg,#16a34a,#15803d);'
                         + 'align-items:center;justify-content:center;'
                         + 'color:#fff;font-weight:700;font-size:16px;flex-shrink:0;'
                }, [ '4N' ]),
                E('div', {}, [
                    E('div', { style: 'font-size:20px;font-weight:700;color:#111827;' }, [ '4eburNet' ]),
                    E('div', { style: 'font-size:13px;color:#6b7280;margin-top:2px;' }, [
                        'v' + ver + '  ·  ' + prof
                    ])
                ])
            ]),

            /* ── Статус и метрики ── */
            E('div', { style: card_style }, [
                E('div', { style: 'display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;' }, [
                    E('div', { style: 'display:flex;align-items:center;gap:8px;' }, [
                        E('span', { style: 'font-size:18px;color:' + dot_color + ';line-height:1;' }, [ '●' ]),
                        E('span', { style: 'font-size:15px;font-weight:600;color:#111827;' }, [ st_label ])
                    ]),
                    E('button', {
                        style: 'border:1px solid #d1d5db;background:#f9fafb;border-radius:6px;'
                             + 'padding:4px 10px;font-size:12px;cursor:pointer;color:#374151;',
                        click: function() { window.location.reload(); }
                    }, [ '↺ Обновить' ])
                ]),
                E('div', { style: 'display:flex;flex-direction:column;gap:6px;' }, [
                    E('div', {}, [
                        E('span', { style: label_style }, [ 'Режим' ]),
                        E('span', { style: value_style }, [ mode ])
                    ]),
                    E('div', {}, [
                        E('span', { style: label_style }, [ 'Аптайм' ]),
                        E('span', { style: value_style }, [ uptime > 0 ? fmt_uptime(uptime) : '—' ])
                    ])
                ])
            ]),

            /* ── Кнопка Dashboard ── */
            E('div', { style: card_style + 'text-align:center;' }, [
                E('button', {
                    style: 'background:#16a34a;color:#fff;border:none;border-radius:8px;'
                         + 'padding:12px 32px;font-size:15px;font-weight:600;cursor:pointer;width:100%;',
                    click: function() {
                        window.open('http://' + location.hostname + ':8080', '_blank');
                    }
                }, [ 'Открыть Dashboard →' ]),
                E('div', { style: 'margin-top:8px;font-size:12px;color:#9ca3af;' }, [
                    'http://' + location.hostname + ':8080'
                ])
            ])

        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
