'use strict';
'require view';
'require uci';

return view.extend({

    load: function() {
        return uci.load('4eburnet');
    },

    render: function() {
        var dns = uci.get('4eburnet', 'dns') || {};

        var row = function(label, value) {
            return E('div', {
                style: 'display:flex;align-items:center;padding:8px 14px;'
                     + 'border-bottom:1px solid #21262d'
            }, [
                E('div', {style: 'flex:1;font-size:11px;color:#8d96a0'}, [label]),
                E('div', {style: 'font-family:monospace;font-size:11px;color:#e6edf3'}, [value || '—'])
            ]);
        };

        return E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:12px'}, [_('DNS настройки')]),
            E('div', {style: 'background:#161b22;border:1px solid #30363d;border-radius:5px'}, [
                row(_('Порт прослушивания'), dns.listen_port),
                row(_('Upstream (bypass)'), dns.upstream_bypass),
                row(_('Upstream (proxy)'), dns.upstream_proxy),
                row(_('DoH URL'), dns.doh_url),
                row(_('Fake-IP диапазон'), dns.fake_ip_range),
                row(_('Кэш'), dns.cache_size ? dns.cache_size + ' записей' : '—'),
                row(_('DoH'), dns.doh_enabled === '1' ? _('Включён') : _('Выключен')),
                row(_('Fake-IP'), dns.fake_ip_enabled === '1' ? _('Включён') : _('Выключен')),
                row(_('Параллельные запросы'), dns.parallel_query === '1' ? _('Да') : _('Нет'))
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
