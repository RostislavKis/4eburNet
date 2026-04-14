'use strict';
'require view';
'require rpc';
'require ui';

var callAdblockStatus = rpc.declare({ object: '4eburnet', method: 'adblock_status' });
var callDnsSet        = rpc.declare({ object: '4eburnet', method: 'dns_set' });
var callGeoUpdate     = rpc.declare({ object: '4eburnet', method: 'geo_update' });
var callStats         = rpc.declare({ object: '4eburnet', method: 'stats' });

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

        var isOn = status.enabled;
        var toggleBtn = E('button', {
            class: isOn ? 'btn cbi-button-negative' : 'btn cbi-button',
            style: 'padding:6px 14px;font-size:12px',
            click: function() {
                var nowOn = toggleBtn.dataset.enabled === '1';
                var newVal = nowOn ? '0' : '1';
                showStatus(_('Применение…'), true);
                callDnsSet({fake_ip_enabled: newVal}).then(function(r) {
                    if (r && r.ok) {
                        toggleBtn.dataset.enabled = newVal;
                        var on = newVal === '1';
                        toggleBtn.textContent = on
                            ? _('Выключить блокировку')
                            : _('Включить блокировку');
                        toggleBtn.className = on
                            ? 'btn cbi-button-negative' : 'btn cbi-button';
                        badgeEl.textContent = on ? _('Включён') : _('Выключен');
                        badgeEl.style.color = on ? '#3ecf6a' : '#8d96a0';
                        showStatus('\u2713 ' + _('Сохранено'), true);
                    } else {
                        showStatus('\u2715 ' + ((r && r.error) || _('ошибка')), false);
                    }
                }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
            }
        }, [isOn ? _('Выключить блокировку') : _('Включить блокировку')]);
        toggleBtn.dataset.enabled = isOn ? '1' : '0';

        var badgeEl = E('span', {
            style: 'font-size:11px;font-weight:600;color:' + (isOn ? '#3ecf6a' : '#8d96a0')
        }, [isOn ? _('Включён') : _('Выключен')]);

        /* Кнопка обновить списки */
        var geoStatusEl = E('div', {
            style: 'font-size:11px;min-height:16px;margin-top:6px'
        }, ['']);
        var geoBtn = E('button', {
            class: 'btn cbi-button',
            style: 'padding:6px 14px;font-size:12px',
            click: function() {
                geoBtn.disabled = true;
                geoStatusEl.textContent = _('Загрузка списков…');
                geoStatusEl.style.color = '#e6edf3';
                callGeoUpdate().then(function(r) {
                    geoBtn.disabled = false;
                    if (r && r.ok) {
                        geoStatusEl.textContent = '\u2713 ' + _('Списки обновлены');
                        geoStatusEl.style.color = '#3ecf6a';
                    } else {
                        geoStatusEl.textContent = '\u2715 ' + ((r && r.error) || _('Ошибка'));
                        geoStatusEl.style.color = '#f85149';
                    }
                }).catch(function(e) {
                    geoBtn.disabled = false;
                    geoStatusEl.textContent = '\u2715 RPC: ' + e;
                    geoStatusEl.style.color = '#f85149';
                });
            }
        }, [_('\uD83D\uDD04 Обновить списки')]);

        /* Статы карточки */
        var ST = 'display:inline-block;font-family:monospace;font-size:18px;font-weight:700;';
        var SL = 'font-size:10px;color:#545d68;margin-top:2px';

        var node = E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:14px'},
                [_('Блокировка рекламы и угроз')]),

            /* Счётчики */
            E('div', {style: 'display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px'}, [
                E('div', {style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:12px;text-align:center'}, [
                    E('div', {id: 'ab-cnt-ads', style: ST + 'color:#3ecf6a'}, [String(status.blocked_ads || 0)]),
                    E('div', {style: SL}, [_('Реклама') + ' (' + (status.ads_count || 0) + ')'])
                ]),
                E('div', {style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:12px;text-align:center'}, [
                    E('div', {id: 'ab-cnt-trackers', style: ST + 'color:#4aa8f0'}, [String(status.blocked_trackers || 0)]),
                    E('div', {style: SL}, [_('Трекеры') + ' (' + (status.trackers_count || 0) + ')'])
                ]),
                E('div', {style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:12px;text-align:center'}, [
                    E('div', {id: 'ab-cnt-threats', style: ST + 'color:#f85149'}, [String(status.blocked_threats || 0)]),
                    E('div', {style: SL}, [_('Угрозы') + ' (' + (status.threats_count || 0) + ')'])
                ])
            ]),

            /* Toggle + update */
            E('div', {style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;padding:14px;margin-bottom:12px'}, [
                E('div', {style: 'display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin-bottom:10px'}, [
                    toggleBtn,
                    badgeEl,
                    statusEl
                ]),
                E('div', {style: 'display:flex;gap:12px;align-items:center;flex-wrap:wrap'}, [
                    geoBtn,
                    geoStatusEl
                ]),
                E('div', {style: 'margin-top:10px;font-size:10px;color:#545d68'}, [
                    _('Источники: oisd.nl (реклама), EasyPrivacy (трекеры), URLhaus (угрозы)')
                ])
            ])
        ]);

        /* Auto-refresh счётчиков каждые 5с */
        var abTimer = setInterval(function() {
            if (!document.getElementById('ab-cnt-ads')) {
                clearInterval(abTimer);
                return;
            }
            callStats().then(function(st) {
                if (!st || st.error) return;
                var el;
                el = document.getElementById('ab-cnt-ads');
                if (el) el.textContent = String(st.blocked_ads || 0);
                el = document.getElementById('ab-cnt-trackers');
                if (el) el.textContent = String(st.blocked_trackers || 0);
                el = document.getElementById('ab-cnt-threats');
                if (el) el.textContent = String(st.blocked_threats || 0);
            }).catch(function() { /* polling не критично */ });
        }, 5000);

        return node;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
