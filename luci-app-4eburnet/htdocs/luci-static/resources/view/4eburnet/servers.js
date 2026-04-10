'use strict';
'require view';

return view.extend({

    render: function() {
        return E('div', {}, [
            E('div', {style: 'font-size:15px;font-weight:600;color:#e6edf3;margin-bottom:12px'}, [
                _('Серверы')
            ]),
            E('div', {
                style: 'background:#161b22;border:1px solid #30363d;border-radius:5px;'
                     + 'padding:24px;text-align:center'
            }, [
                E('div', {style: 'font-size:13px;color:#8d96a0;margin-bottom:8px'}, ['🚧']),
                E('div', {style: 'font-size:12px;color:#545d68'}, [
                    _('Управление серверами — в разработке.')
                ]),
                E('div', {style: 'font-size:11px;color:#30363d;margin-top:6px'}, [
                    _('Добавьте серверы в UCI конфиг: /etc/config/4eburnet')
                ])
            ])
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
