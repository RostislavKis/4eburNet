'use strict';
'require view';
'require form';
'require uci';

return view.extend({

    load: function() {
        return uci.load('4eburnet');
    },

    render: function() {
        var m = new form.Map('4eburnet', _('Настройки 4eburNet'));

        var s = m.section(form.TypedSection, '4eburnet', _('Основные'));
        s.anonymous = true;

        var en = s.option(form.Flag, 'enabled', _('Включить'));
        en.rmempty = false;

        var mode = s.option(form.ListValue, 'mode', _('Режим'));
        mode.value('rules',  _('По правилам'));
        mode.value('global', _('Глобальный'));
        mode.value('direct', _('Напрямую'));

        var ll = s.option(form.ListValue, 'log_level', _('Уровень логирования'));
        ll.value('debug', 'debug');
        ll.value('info',  'info');
        ll.value('warn',  'warn');
        ll.value('error', 'error');

        var iface = s.option(form.Value, 'lan_interface', _('LAN интерфейс'));
        iface.placeholder = 'br-lan';

        var region = s.option(form.ListValue, 'region', _('Регион GeoIP'));
        region.value('ru', 'RU');
        region.value('cn', 'CN');
        region.value('us', 'US');

        return m.render();
    }
});
