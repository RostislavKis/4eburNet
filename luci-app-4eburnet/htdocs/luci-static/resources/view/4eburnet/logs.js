'use strict';
'require view';
'require rpc';
'require ui';

var callLogs = rpc.declare({ object: '4eburnet', method: 'logs', params: ['lines'] });

function escHtml(s) {
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function renderLines(lines, lvl, search) {
    var colorMap = {
        debug: '#545d68', info: '#4aa8f0', warn: '#f0b429', error: '#f85149'
    };
    return lines.filter(function(l) {
        var ll = l.toLowerCase();
        return (!lvl || ll.indexOf('[' + lvl + ']') !== -1)
            && (!search || ll.indexOf(search) !== -1);
    }).map(function(l) {
        var m = l.match(/^(\d{2}:\d{2}:\d{2})\s+\[(DEBUG|INFO|WARN|ERROR)\]\s*(.*)/i);
        var ts  = m ? m[1] : '';
        var lv  = m ? m[2].toLowerCase() : 'info';
        var msg = m ? m[3] : l;
        var col = colorMap[lv] || '#e6edf3';
        return '<div style="display:flex;gap:8px;line-height:1.65;padding:1px 0">'
            + '<span style="color:#545d68;flex-shrink:0;min-width:56px">' + escHtml(ts) + '</span>'
            + '<span style="color:' + col + ';min-width:44px;font-weight:600;flex-shrink:0">' + lv.toUpperCase() + '</span>'
            + '<span style="color:#e6edf3;word-break:break-all">' + escHtml(msg) + '</span>'
            + '</div>';
    }).join('');
}

return view.extend({

    load: function() {
        return callLogs(100);
    },

    render: function(logData) {
        var allLines = (logData || {}).lines || [];

        var area = E('div', {
            style: 'background:#0a0d11;border:1px solid #30363d;border-radius:5px;'
                 + 'font-family:monospace;font-size:11px;height:420px;'
                 + 'overflow-y:auto;padding:10px;line-height:1.65'
        });

        var lvSel = E('select', {
            style: 'padding:4px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px',
            change: function() { doUpdate(); }
        }, [
            E('option', {value: ''}, [_('Все уровни')]),
            E('option', {value: 'debug'}, ['DEBUG']),
            E('option', {value: 'info'},  ['INFO']),
            E('option', {value: 'warn'},  ['WARN']),
            E('option', {value: 'error'}, ['ERROR'])
        ]);

        var searchInp = E('input', {
            type: 'text', placeholder: _('Поиск…'),
            style: 'padding:4px 8px;background:#21262d;border:1px solid #30363d;'
                 + 'border-radius:4px;color:#e6edf3;font-size:11px;width:180px',
            input: function() { doUpdate(); }
        });

        var countSpan = E('span', {style: 'font-size:10px;color:#545d68;margin-left:4px'},
            [_('Строк: '), E('span', {id: 'log-count-val'}, [String(allLines.length)])]);

        function doUpdate() {
            area.innerHTML = renderLines(
                allLines,
                lvSel.value,
                searchInp.value.toLowerCase()
            );
            area.scrollTop = area.scrollHeight;
            var el = document.getElementById('log-count-val');
            if (el) el.textContent = String(allLines.length);
        }

        doUpdate();

        /* Polling через setInterval с cleanup в handleReset */
        var pollTimer = setInterval(function() {
            callLogs(100).then(function(resp) {
                if (!resp || !resp.lines) return;
                /* Если DOM ушёл — остановить таймер */
                if (!document.getElementById('log-count-val')) {
                    clearInterval(pollTimer);
                    return;
                }
                allLines = resp.lines;
                doUpdate();
            }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
        }, 3000);

        var node = E('div', {'data-poll-timer': String(pollTimer)}, [
            E('div', {
                style: 'display:flex;gap:10px;margin-bottom:10px;align-items:center;flex-wrap:wrap'
            }, [
                lvSel,
                searchInp,
                E('button', {
                    class: 'btn cbi-button',
                    style: 'padding:4px 9px;font-size:11px',
                    click: function() {
                        callLogs(100).then(function(resp) {
                            if (resp && resp.lines) { allLines = resp.lines; doUpdate(); }
                        }).catch(function(e) { ui.addNotification(null, E('p', {}, ['RPC: ' + e]), 'danger'); });
                    }
                }, ['⟳ ' + _('Обновить')]),
                countSpan
            ]),
            area
        ]);

        return node;
    },

    handleSaveApply: null,
    handleSave: null,

    handleReset: function() {
        /* Остановить polling при уходе со страницы */
        var node = document.querySelector('[data-poll-timer]');
        if (node && node.dataset.pollTimer) {
            clearInterval(parseInt(node.dataset.pollTimer, 10));
            delete node.dataset.pollTimer;
        }
    }
});
