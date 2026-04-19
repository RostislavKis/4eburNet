'use strict';
'require view';

/* LuCI вкладка — редирект на встроенный Dashboard :8080
 * rpcd/ucode не требуется */
return view.extend({
    render: function() {
        var dashUrl = window.location.protocol + '//'
                    + window.location.hostname + ':8080/';
        window.location.href = dashUrl;
        return E('div', { 'style': 'padding:20px;font-family:system-ui,sans-serif;' }, [
            E('p', {}, '⟳ Открываю 4eburNet Dashboard...'),
            E('a', { 'href': dashUrl }, dashUrl)
        ]);
    },

    handleSaveApply: null,
    handleSave: null,
    handleReset: null
});
