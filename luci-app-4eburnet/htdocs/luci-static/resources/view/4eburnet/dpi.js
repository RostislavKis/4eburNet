'use strict';
'require view';
'require rpc';
'require ui';

var callDpiGet    = rpc.declare({ object: '4eburnet', method: 'dpi_get' });
var callDpiSet    = rpc.declare({ object: '4eburnet', method: 'dpi_set' });
var callCdnUpdate = rpc.declare({ object: '4eburnet', method: 'cdn_update' });
var callReload    = rpc.declare({ object: '4eburnet', method: 'reload' });

function sel(id) { return document.getElementById(id); }

function numVal(id, def) {
    var v = parseInt(sel(id).value, 10);
    return isNaN(v) ? def : '' + v;
}

function mkInput(id, val, mono) {
    return E('input', {
        id: id, type: 'text', value: val || '',
        style: 'width:100%;padding:6px 10px;background:#21262d;'
             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
             + 'font-size:12px;'
             + (mono ? 'font-family:monospace,' : '')
             + 'inherit;outline:none;box-sizing:border-box'
    });
}

function mkNumber(id, val, min, max) {
    return E('input', {
        id: id, type: 'number', value: val || '',
        min: min, max: max,
        style: 'width:120px;padding:6px 10px;background:#21262d;'
             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
             + 'font-size:12px;font-family:monospace,inherit;outline:none;box-sizing:border-box'
    });
}

function mkRow(label, content) {
    return E('div', {
        style: 'display:flex;gap:12px;margin-bottom:10px;align-items:flex-start'
    }, [
        E('div', {style: 'min-width:180px;font-size:11px;color:#8d96a0;padding-top:8px;flex-shrink:0'}, [label]),
        E('div', {style: 'flex:1;min-width:0'}, [content])
    ]);
}

function mkStatRow(label, value, valueId) {
    return E('div', {
        style: 'display:flex;justify-content:space-between;padding:6px 0;'
             + 'border-bottom:1px solid #21262d'
    }, [
        E('span', {style: 'font-size:12px;color:#8d96a0'}, [label]),
        E('span', {id: valueId || null, style: 'font-size:12px;color:#e6edf3;font-family:monospace'}, [value])
    ]);
}

function card(title, rows) {
    return E('div', {
        style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;'
             + 'padding:16px;margin-bottom:14px'
    }, [
        E('div', {
            style: 'font-size:11px;font-weight:600;color:#8d96a0;'
                 + 'text-transform:uppercase;letter-spacing:.7px;margin-bottom:14px'
        }, [title]),
        E('div', {}, rows)
    ]);
}

function formatTimestamp(ts) {
    if (!ts) return '\u2014';
    var d = new Date(ts * 1000);
    var pad = function(n) { return n < 10 ? '0' + n : '' + n; };
    return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate())
         + ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes());
}

return view.extend({

    load: function() {
        return callDpiGet();
    },

    render: function(cfg) {
        cfg = cfg || {};

        var node = E('div', {}, [

            /* Карточка 1: Настройки обхода DPI */
            card('\uD83D\uDEE1 Настройки обхода DPI', [
                mkRow(_('Включить DPI bypass'),
                    E('div', {style: 'display:flex;align-items:center;gap:10px'}, [
                        E('input', {
                            type: 'checkbox', id: 'dpi-enabled',
                            checked: cfg.dpi_enabled === '1' ? '' : null,
                            style: 'width:16px;height:16px;cursor:pointer'
                        }),
                        E('span', {style: 'font-size:12px;color:#e6edf3'},
                            [_('Применять fake+fragment для DIRECT соединений')])
                    ])
                ),
                mkRow(_('Split position (байт)'),
                    mkNumber('dpi-split-pos', cfg.dpi_split_pos || '1', 1, 1400)
                ),
                mkRow(_('Fake TTL'),
                    mkNumber('dpi-ttl', cfg.dpi_fake_ttl || '5', 1, 64)
                ),
                mkRow(_('Fake повторений'),
                    mkNumber('dpi-repeats', cfg.dpi_fake_repeats || '8', 1, 20)
                ),
                mkRow(_('Fake SNI'),
                    mkInput('dpi-sni', cfg.dpi_fake_sni || 'www.google.com', true)
                ),
                mkRow(_('Директория DPI файлов'),
                    mkInput('dpi-dir', cfg.dpi_dir || '/etc/4eburnet/dpi', true)
                ),
                E('div', { style: 'margin-top:14px' }, [
                    E('button', {
                        class: 'btn cbi-button',
                        click: function() {
                            callDpiSet({
                                dpi_enabled:      sel('dpi-enabled') && sel('dpi-enabled').checked ? '1' : '0',
                                dpi_split_pos:    numVal('dpi-split-pos', '1'),
                                dpi_fake_ttl:     numVal('dpi-ttl', '5'),
                                dpi_fake_repeats: numVal('dpi-repeats', '8'),
                                dpi_fake_sni:     sel('dpi-sni').value,
                                dpi_dir:          sel('dpi-dir').value
                            }).then(function(r) {
                                if (r && r.ok) {
                                    callReload();
                                    ui.addNotification(null,
                                        E('p', {}, [_('Настройки DPI сохранены')]), 'info');
                                }
                            }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                        }
                    }, [_('\uD83D\uDCBE Сохранить')])
                ])
            ]),

            /* Карточка 2: CDN IP автообновление */
            card('\uD83D\uDCE1 CDN IP автообновление', [
                E('div', { style: 'font-size:11px;color:#8d96a0;margin-bottom:12px' }, [
                    _('CDN IP диапазоны загружаются из Cloudflare и Fastly. '),
                    _('Используются для автоматического DPI bypass без ручной настройки.')
                ]),
                mkRow(_('Интервал обновления (дней)'),
                    mkNumber('cdn-interval', cfg.cdn_update_interval_days || '7', 0, 365)
                ),
                mkRow(_('Cloudflare IPv4 URL'),
                    E('input', {
                        id: 'cdn-cf-v4', type: 'text', value: cfg.cdn_cf_v4_url || '',
                        placeholder: 'https://www.cloudflare.com/ips-v4 (' + _('по умолчанию') + ')',
                        style: 'width:100%;padding:6px 10px;background:#21262d;'
                             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
                             + 'font-size:12px;font-family:monospace,inherit;outline:none;box-sizing:border-box'
                    })
                ),
                mkRow(_('Cloudflare IPv6 URL'),
                    E('input', {
                        id: 'cdn-cf-v6', type: 'text', value: cfg.cdn_cf_v6_url || '',
                        placeholder: 'https://www.cloudflare.com/ips-v6 (' + _('по умолчанию') + ')',
                        style: 'width:100%;padding:6px 10px;background:#21262d;'
                             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
                             + 'font-size:12px;font-family:monospace,inherit;outline:none;box-sizing:border-box'
                    })
                ),
                mkRow(_('Fastly URL'),
                    E('input', {
                        id: 'cdn-fastly', type: 'text', value: cfg.cdn_fastly_url || '',
                        placeholder: 'https://api.fastly.com/public-ip-list (' + _('по умолчанию') + ')',
                        style: 'width:100%;padding:6px 10px;background:#21262d;'
                             + 'border:1px solid #30363d;border-radius:4px;color:#e6edf3;'
                             + 'font-size:12px;font-family:monospace,inherit;outline:none;box-sizing:border-box'
                    })
                ),
                E('div', { style: 'margin-top:14px;display:flex;gap:8px;flex-wrap:wrap' }, [
                    E('button', {
                        class: 'btn cbi-button',
                        click: function() {
                            callDpiSet({
                                cdn_update_interval_days: numVal('cdn-interval', '7'),
                                cdn_cf_v4_url:            sel('cdn-cf-v4').value,
                                cdn_cf_v6_url:            sel('cdn-cf-v6').value,
                                cdn_fastly_url:           sel('cdn-fastly').value
                            }).then(function(r) {
                                if (r && r.ok) {
                                    callReload();
                                    ui.addNotification(null,
                                        E('p', {}, [_('Настройки CDN сохранены')]), 'info');
                                }
                            }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                        }
                    }, [_('\uD83D\uDCBE Сохранить CDN')]),
                    E('button', {
                        id: 'cdn-update-btn',
                        class: 'btn cbi-button-negative',
                        click: function() {
                            var btn = sel('cdn-update-btn');
                            var st  = sel('cdn-status');
                            if (btn) btn.disabled = true;
                            if (st) { st.textContent = _('Обновление запланировано...'); st.style.color = '#e6edf3'; }
                            callCdnUpdate().then(function(r) {
                                if (btn) btn.disabled = false;
                                if (r && r.ok) {
                                    if (st) { st.textContent = '\u2713 ' + (r.msg || _('Запущено')); st.style.color = '#3ecf6a'; }
                                    /* Обновить статистику через 5 сек (дождаться fork) */
                                    setTimeout(function() {
                                        callDpiGet().then(function(data) {
                                            if (!data) return;
                                            var ipset = sel('stat-ipset');
                                            var wl    = sel('stat-wl');
                                            var ah    = sel('stat-ah');
                                            var upd   = sel('stat-updated');
                                            if (ipset) ipset.textContent = data.ipset_lines != null ? '' + data.ipset_lines : '\u2014';
                                            if (wl)    wl.textContent    = data.whitelist_count != null ? '' + data.whitelist_count : '\u2014';
                                            if (ah)    ah.textContent    = data.autohosts_count != null ? '' + data.autohosts_count : '\u2014';
                                            if (upd)   upd.textContent   = formatTimestamp(data.ipset_updated);
                                        }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                                    }, 5000);
                                } else {
                                    if (st) { st.textContent = '\u2715 ' + (r && r.error || _('Ошибка')); st.style.color = '#f85149'; }
                                }
                            }).catch(function(e) { if (btn) btn.disabled = false; ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                        }
                    }, [_('\u21BB Обновить CDN сейчас')])
                ]),
                E('div', { id: 'cdn-status', style: 'font-size:11px;margin-top:8px;min-height:16px' }, [''])
            ]),

            /* Карточка 3: Статистика DPI фильтра */
            card('\uD83D\uDCCA Статистика DPI фильтра', [
                mkStatRow(_('Строк в ipset.txt (CDN IP)'),
                    cfg.ipset_lines != null ? '' + cfg.ipset_lines : '\u2014', 'stat-ipset'),
                mkStatRow(_('Доменов в whitelist'),
                    cfg.whitelist_count != null ? '' + cfg.whitelist_count : '\u2014', 'stat-wl'),
                mkStatRow(_('Доменов в autohosts'),
                    cfg.autohosts_count != null ? '' + cfg.autohosts_count : '\u2014', 'stat-ah'),
                mkStatRow(_('Последнее обновление CDN IP'),
                    formatTimestamp(cfg.ipset_updated), 'stat-updated')
            ])
        ]);

        return node;
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
