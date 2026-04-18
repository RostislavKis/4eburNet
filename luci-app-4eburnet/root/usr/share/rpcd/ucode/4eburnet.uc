'use strict';

import * as fs  from 'fs';
import * as uci from 'uci';

// ── Константы ──────────────────────────────────────────────────────
const EBURNETD = '/usr/sbin/4eburnetd';

// ── Утилиты ────────────────────────────────────────────────────────

// Выполнить команду и вернуть первую строку вывода
function shell_line(cmd) {
    let f = fs.popen(cmd + ' 2>/dev/null');
    if (!f) return null;
    let s = f.read('line');
    f.close();
    return s ? replace(s, /\n$/, '') : null;
}

// Безопасный uci_get_section
function uci_get_section(config, section) {
    let c = uci.cursor();
    let result = {};
    c.foreach(config, null, function(s) {
        if (s['.name'] == section) {
            for (let k in s)
                result[k] = s[k];
        }
    });
    return result;
}

// Проверить жив ли демон (без system() — не блокировать rpcd)
function is_running() {
    let f = fs.open('/var/run/4eburnet.pid', 'r');
    if (!f) return false;
    let ipid = int(f.read('line'));
    f.close();
    if (!ipid || ipid <= 0) return false;
    let cf = fs.open('/proc/' + ipid + '/comm', 'r');
    if (!cf) return false;
    let comm = trim(cf.read('line') ?? '');
    cf.close();
    return comm == '4eburnetd';
}

// ── IPC через CLI ──────────────────────────────────────────────────

const IPC_CMDS = { 'status': true };

// Вызвать 4eburnetd --ipc <cmd> через CLI
function ipc_json(cmd_name) {
    if (!IPC_CMDS[cmd_name]) return { error: 'unknown command: ' + cmd_name };
    if (!is_running()) return { error: 'daemon not running' };
    let f = fs.popen(EBURNETD + ' --ipc ' + cmd_name + ' 2>/dev/null');
    if (!f) return { error: 'popen failed' };
    let out = f.read('all');
    f.close();
    if (!out || length(trim(out)) == 0) return { error: 'empty response' };
    let d = json(trim(out));
    return d ?? { error: 'json parse error' };
}

// ── Методы ─────────────────────────────────────────────────────────

const methods = {

    status: {
        call: function(req) {
            let mode_uci = uci_get_section('4eburnet', 'main')['mode'] ?? 'rules';
            if (!is_running())
                return { status: 'stopped', uptime: 0, version: 'unknown',
                         mode: mode_uci, profile: 'unknown' };
            let d = ipc_json('status');
            if (d.error)
                return { status: 'error', uptime: 0, version: 'unknown',
                         mode: mode_uci, profile: 'unknown' };
            return {
                status:  'running',
                version: d.version ?? 'unknown',
                uptime:  d.uptime  ?? 0,
                mode:    d.mode    ?? mode_uci,
                profile: d.profile ?? 'unknown',
            };
        }
    },

    /* REMOVED: dashboard moved to :8080
       stats, reload, stop, restart, start, geo_update, tproxy_status,
       pkg_manager, wan_ip, logs, devices, device_save, server_list,
       server_add, server_delete, rules_list, rule_add, rule_delete,
       groups, group_select, providers, provider_update, geo_status,
       dpi_get, dpi_set, cdn_update, dns_get, dns_set, config_get,
       config_set, adblock_status, backup_status, backup, restore,
       subscription_import
    */

};

return { '4eburnet': methods };
