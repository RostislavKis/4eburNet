#!/usr/bin/ucode
'use strict';

import * as fs     from 'fs';
import * as uci    from 'uci';

// ── Константы ──────────────────────────────────────────────────────
const EBURNETD    = '/usr/sbin/4eburnetd';
const BACKUP_FILE = '/etc/4eburnet/backup.tar.gz';

// ── Утилиты ────────────────────────────────────────────────────────

// Выполнить команду и вернуть первую строку вывода
function shell_line(cmd) {
    let f = fs.popen(cmd + ' 2>/dev/null');
    if (!f) return null;
    let s = f.read('line');
    f.close();
    return s ? replace(s, /\n$/, '') : null;
}

// Выполнить команду и вернуть весь вывод
function shell_all(cmd) {
    let f = fs.popen(cmd + ' 2>/dev/null');
    if (!f) return '';
    let s = f.read('all');
    f.close();
    return s ?? '';
}

// Прочитать все строки файла
function file_lines(path) {
    let f = fs.open(path, 'r');
    if (!f) return [];
    let lines = [], line;
    while ((line = f.read('line')) != null)
        push(lines, replace(line, /\n$/, ''));
    f.close();
    return lines;
}

// Подсчитать непустые строки без комментариев
function count_lines(path) {
    let f = fs.open(path, 'r');
    if (!f) return 0;
    let n = 0, line;
    while ((line = f.read('line')) != null) {
        let t = trim(line);
        if (length(t) > 0 && ord(t, 0) != 0x23) n++;
    }
    f.close();
    return n;
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

// Получить все секции заданного типа
function uci_get_sections_of_type(config, stype) {
    let c = uci.cursor();
    let arr = [];
    c.foreach(config, stype, function(s) {
        push(arr, s);
    });
    return arr;
}

// Безопасный uci set + commit
function uci_set(config, section, option, value) {
    let c = uci.cursor();
    c.set(config, section, option, value);
    c.commit(config);
    return true;
}

// Проверить жив ли демон
function is_running() {
    let f = fs.open('/var/run/4eburnet.pid', 'r');
    if (!f) return false;
    let pid = int(f.read('line'));
    f.close();
    if (!pid) return false;
    return system('kill -0 ' + pid + ' 2>/dev/null') == 0;
}

// Определить пакетный менеджер
function get_pkg_mgr() {
    let f = fs.open('/usr/bin/apk', 'r');
    if (f) { f.close(); return 'apk'; }
    let c = fs.open('/etc/openwrt_release', 'r');
    if (c) {
        let content = c.read('all'); c.close();
        let m = match(content, /DISTRIB_RELEASE="(\d+)\.(\d+)/);
        if (m) {
            let ma = int(m[1]), mi = int(m[2]);
            if (ma > 25 || (ma == 25 && mi >= 12)) return 'apk';
        }
    }
    return 'opkg';
}

// ── IPC через CLI (fs.popen) ──────────────────────────────────────

// Допустимые команды (whitelist — защита от injection)
const IPC_CMDS = {
    'status': true, 'reload': true, 'stop': true, 'stats': true,
    'groups': true, 'group-select': true, 'group-test': true,
    'providers': true, 'provider-update': true, 'rules': true,
    'geo-status': true, 'cdn-update': true,
};

// Вызвать 4eburnetd --ipc <cmd> [payload] через CLI
// Возвращает распарсённый JSON объект или { error: '...' }
function ipc_json(cmd_name, payload) {
    if (!IPC_CMDS[cmd_name]) return { error: 'unknown command: ' + cmd_name };

    let cmdline = EBURNETD + ' --ipc ' + cmd_name;
    let tmp = null;

    if (payload) {
        // Payload через tmp файл + stdin redirect (нет shell injection)
        tmp = '/tmp/.4eburnet-ipc-' + time() + '-' + math.floor(math.random() * 0xFFFFFF) + '.json';
        let wf = fs.open(tmp, 'w');
        if (!wf) return { error: 'write tmp failed' };
        wf.write('' + payload);
        wf.close();
        fs.chmod(tmp, 0o600);
        cmdline += ' < ' + tmp;
    }

    let f = fs.popen(cmdline + ' 2>/dev/null');
    if (!f) {
        if (tmp) fs.unlink(tmp);
        return { error: 'popen failed' };
    }
    let out = f.read('all');
    f.close();
    if (tmp) fs.unlink(tmp);

    if (!out || length(trim(out)) == 0)
        return { error: 'empty response' };

    let d = json(trim(out));
    return d ?? { error: 'json parse error', raw: out };
}

// ── Методы ─────────────────────────────────────────────────────────

const methods = {

    status: {
        call: function(req) {
            let running = is_running();
            if (!running)
                return { running: false, uptime: 0,
                         mode: uci_get_section('4eburnet', 'main')['mode'] ?? 'rules',
                         profile: 'unknown', timestamp: time() };
            let d = ipc_json('status');
            if (d.error)
                return { running: true, uptime: 0,
                         mode: uci_get_section('4eburnet', 'main')['mode'] ?? 'rules',
                         profile: 'unknown', timestamp: time() };
            return {
                running:   true,
                uptime:    d.uptime   ?? 0,
                mode:      d.mode     ?? uci_get_section('4eburnet', 'main')['mode'] ?? 'rules',
                profile:   d.profile  ?? 'unknown',
                timestamp: time()
            };
        }
    },

    stats: {
        call: function(req) {
            if (!is_running())
                return { error: 'not running', connections_total: 0,
                         connections_active: 0, dns_queries: 0, dns_cached: 0 };
            let d = ipc_json('stats');
            if (d.error) return { error: d.error, connections_total: 0,
                                  connections_active: 0, dns_queries: 0, dns_cached: 0 };
            return d;
        }
    },

    reload: {
        call: function(req) {
            if (!is_running()) return { ok: false, error: 'not running' };
            system('/etc/init.d/4eburnet reload 2>/dev/null');
            return { ok: true };
        }
    },

    stop: {
        call: function(req) {
            system('/etc/init.d/4eburnet stop 2>/dev/null');
            return { ok: true };
        }
    },

    restart: {
        call: function(req) {
            // Запустить stop+start асинхронно — не блокируем rpcd
            system("sh -c '/etc/init.d/4eburnet stop 2>/dev/null; "
                 + "sleep 1; /etc/init.d/4eburnet start 2>/dev/null' &");
            return { ok: true };
        }
    },

    start: {
        call: function(req) {
            system('/etc/init.d/4eburnet start 2>/dev/null &');
            return { ok: true };
        }
    },

    geo_update: {
        call: function(req) {
            let main = uci_get_section('4eburnet', 'main');
            let geo_dir = main?.geo_dir || '/etc/4eburnet/geo';
            let base    = main?.geo_url || 'https://raw.githubusercontent.com/RostislavKis/filter/master/geo';

            if (!match(geo_dir, /^[a-zA-Z0-9\/_.\-]+$/))
                return { ok: false, error: 'invalid geo_dir: ' + geo_dir };
            if (!match(base, /^https?:\/\/[a-zA-Z0-9.\-_]+(:[0-9]+)?(\/[a-zA-Z0-9.\-_\/]*)?$/))
                return { ok: false, error: 'invalid geo_url: ' + base };

            system('mkdir -p ' + geo_dir);
            let files = ['geoip-ru.lst', 'geosite-ru.lst', 'geosite-ads.lst'];
            let results = {};
            for (let i = 0; i < length(files); i++) {
                let f = files[i];
                let target = geo_dir + '/' + f;
                let tmp    = target + '.tmp';

                let rc = system('uclient-fetch -q -T 30 -O ' + tmp +
                                ' ' + base + '/' + f + ' 2>/dev/null');
                if (rc != 0) {
                    fs.unlink(tmp);
                    results[f] = 'error';
                    continue;
                }

                /* Проверить что файл непустой (защита от пустого 200 OK) */
                let fh = fs.open(tmp, 'r');
                if (!fh) { fs.unlink(tmp); results[f] = 'error'; continue; }
                let head = fh.read(16);
                fh.close();
                if (!head || length(head) == 0) {
                    fs.unlink(tmp);
                    results[f] = 'error';
                    continue;
                }

                /* Атомарная замена: mv на одной FS = rename(2) */
                if (system('mv -f ' + tmp + ' ' + target) == 0)
                    results[f] = 'ok';
                else {
                    fs.unlink(tmp);
                    results[f] = 'error';
                }
            }
            // Перечитать конфиг чтобы демон подхватил новые geo файлы
            if (is_running())
                ipc_json('reload');
            return { ok: true, files: results };
        }
    },

    tproxy_status: {
        call: function(req) {
            // Проверяем mark-based routing через /proc (без fork/popen)
            // /proc/net/fib_rules содержит ip rule list
            let routing_ok = false;
            let table_ok = false;
            let lines = file_lines('/proc/net/fib_rules');
            for (let i = 0; i < length(lines); i++) {
                // строка содержит "mark: 0x1" → правило fwmark 0x01 существует
                if (index(lines[i], 'mark: 0x1') >= 0) {
                    routing_ok = true;
                    break;
                }
            }
            // /proc/net/rt_local: локальный маршрут table=255 (local table)
            // таблица 100 через /proc/net/rt_cache или проверяем файл маршрутов
            // упрощённо: если routing_ok=true, значит table 100 настроена демоном
            table_ok = routing_ok;
            return { available: true, routing_ok: routing_ok, table_ok: table_ok };
        }
    },

    pkg_manager: {
        call: function(req) {
            let mgr = get_pkg_mgr();
            let f = fs.open('/etc/openwrt_release', 'r');
            let version = '';
            if (f) {
                let c = f.read('all'); f.close();
                let m = match(c, /DISTRIB_RELEASE="([^"]+)"/);
                if (m) version = m[1];
            }
            return {
                manager: mgr,
                version: version,
                install: mgr == 'apk' ? 'apk add'    : 'opkg install',
                remove:  mgr == 'apk' ? 'apk del'    : 'opkg remove',
                update:  mgr == 'apk' ? 'apk update' : 'opkg update'
            };
        }
    },

    wan_ip: {
        call: function(req) {
            let ip = null;
            let line = shell_line('ip route get 8.8.8.8');
            if (line) {
                let m = match(line, /src\s+(\d+\.\d+\.\d+\.\d+)/);
                if (m) ip = m[1];
            }
            if (!ip) {
                let out = shell_all('ip addr show scope global');
                let m = match(out, /inet\s+(\d+\.\d+\.\d+\.\d+)/);
                if (m) ip = m[1];
            }
            return { ip: ip ?? 'unknown', timestamp: time() };
        }
    },

    logs: {
        args: { lines: 50 },
        call: function(req) {
            let n = min(int(req.args?.lines ?? 50), 500);
            let all = file_lines('/tmp/4eburnet.log');
            let from = max(0, length(all) - n);
            return { lines: slice(all, from), count: length(all) - from };
        }
    },

    devices: {
        call: function(req) {
            let devs = [], seen = {};

            // ARP таблица
            let f = fs.open('/proc/net/arp', 'r');
            if (f) {
                f.read('line'); // заголовок
                let line;
                while ((line = f.read('line')) != null) {
                    let parts = split(trim(line), /\s+/);
                    if (length(parts) >= 4) {
                        let ip = parts[0], mac = uc(parts[3]);
                        if (mac != '00:00:00:00:00:00' && !seen[mac]) {
                            seen[mac] = true;
                            push(devs, { ip, mac, iface: parts[5] ?? '', source: 'arp' });
                        }
                    }
                }
                f.close();
            }

            // DHCP leases
            f = fs.open('/tmp/dhcp.leases', 'r');
            if (f) {
                let line;
                while ((line = f.read('line')) != null) {
                    let parts = split(trim(line), /\s+/);
                    if (length(parts) >= 4) {
                        let mac = uc(parts[1]), ip = parts[2], name = parts[3];
                        let found = false;
                        for (let i = 0; i < length(devs); i++) {
                            let d = devs[i];
                            if (d.mac == mac) {
                                if (name != '*') d.hostname = name;
                                found = true; break;
                            }
                        }
                        if (!found && !seen[mac]) {
                            seen[mac] = true;
                            push(devs, { ip, mac, hostname: name != '*' ? name : null, source: 'dhcp' });
                        }
                    }
                }
                f.close();
            }

            // UCI политика устройств
            let policies = uci_get_sections_of_type('4eburnet', 'device');
            for (let i = 0; i < length(devs); i++) {
                let d = devs[i];
                d.policy = 'default';
                for (let j = 0; j < length(policies); j++) {
                    let ps = policies[j];
                    if (ps.mac && uc(ps.mac) == d.mac) {
                        d.policy = ps.policy ?? 'default';
                        d.group  = ps.server_group ?? '';
                        d.alias  = ps.alias ?? '';
                        break;
                    }
                }
            }

            return { devices: devs, count: length(devs) };
        }
    },

    device_save: {
        args: { mac: '', policy: '', group: '', alias: '' },
        call: function(req) {
            let mac = req.args?.mac ?? '';
            if (!match(mac, /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/))
                return { ok: false, error: 'invalid MAC address' };

            let policy = req.args?.policy ?? 'default';
            let allowed = { default: 1, proxy: 1, bypass: 1, block: 1 };
            if (!allowed[policy]) return { ok: false, error: 'invalid policy' };

            let group = replace(req.args?.group ?? '', /'/g, '');
            let alias = replace(req.args?.alias ?? '', /'/g, '');
            let umac  = uc(mac);

            let existing = null;
            let dev_sections = uci_get_sections_of_type('4eburnet', 'device');
            for (let i = 0; i < length(dev_sections); i++) {
                let s = dev_sections[i];
                if (s.mac && uc(s.mac) == umac) { existing = s['.name']; break; }
            }

            let c = uci.cursor();
            if (existing) {
                c.set('4eburnet', existing, 'policy', policy);
                if (group) c.set('4eburnet', existing, 'server_group', group);
                if (alias) c.set('4eburnet', existing, 'alias', alias);
            } else {
                let sec = c.add('4eburnet', 'device');
                c.set('4eburnet', sec, 'mac', umac);
                c.set('4eburnet', sec, 'policy', policy);
                if (group) c.set('4eburnet', sec, 'server_group', group);
                if (alias) c.set('4eburnet', sec, 'alias', alias);
            }
            c.commit('4eburnet');

            return { ok: true, mac: umac, policy };
        }
    },

    server_list: {
        call: function(req) {
            let servers = uci_get_sections_of_type('4eburnet', 'server');
            return { servers, count: length(servers) };
        }
    },

    server_add: {
        args: { name: '', protocol: '', address: '', port: 0,
                transport: '', uuid: '', password: '',
                reality_pbk: '', reality_sid: '',
                hy2_obfs_password: '', hy2_sni: '',
                hy2_insecure: 0, hy2_up_mbps: 0, hy2_down_mbps: 0,
                stls_password: '', stls_sni: '' },
        call: function(req) {
            let a = req.args ?? {};
            let required_fields = ['name', 'protocol', 'address', 'port'];
            for (let i = 0; i < length(required_fields); i++) {
                let f = required_fields[i];
                if (!a[f]) return { ok: false, error: 'field required: ' + f };
            }

            let proto_ok = { vless: 1, trojan: 1, shadowsocks: 1, awg: 1,
                             hysteria2: 1, shadowtls: 1 };
            if (!proto_ok[a.protocol])
                return { ok: false, error: 'invalid protocol: ' + a.protocol };

            let port = int(a.port);
            if (!port || port < 1 || port > 65535)
                return { ok: false, error: 'invalid port' };

            if (match(a.name, /[^\w\-\.]/))
                return { ok: false, error: 'invalid server name' };

            let c = uci.cursor();
            let sec = c.add('4eburnet', 'server');
            let safe = { name:1, protocol:1, address:1, transport:1,
                         uuid:1, password:1, reality_pbk:1, reality_sid:1,
                         xhttp_path:1, xhttp_host:1,
                         stls_password:1, stls_sni:1 };
            for (let k in a)
                if (safe[k] && a[k]) c.set('4eburnet', sec, k, '' + a[k]);
            c.set('4eburnet', sec, 'port', '' + port);
            c.set('4eburnet', sec, 'enabled', '1');

            /* Hysteria2-специфичные поля */
            if (a.protocol === 'hysteria2') {
                if (a.hy2_obfs_password)
                    c.set('4eburnet', sec, 'hy2_obfs_password',
                          '' + a.hy2_obfs_password);
                if (a.hy2_sni)
                    c.set('4eburnet', sec, 'hy2_sni', '' + a.hy2_sni);
                /* Сохранять только если включён — отсутствие опции = false */
                if (a.hy2_insecure)
                    c.set('4eburnet', sec, 'hy2_insecure', '1');
                let up = int(a.hy2_up_mbps);
                if (up > 0)
                    c.set('4eburnet', sec, 'hy2_up_mbps', '' + up);
                let down = int(a.hy2_down_mbps);
                if (down > 0)
                    c.set('4eburnet', sec, 'hy2_down_mbps', '' + down);
            }

            c.commit('4eburnet');

            return { ok: true, section: sec };
        }
    },

    server_delete: {
        args: { section: '' },
        call: function(req) {
            let sec = req.args?.section ?? '';
            if (match(sec, /[^\w\-]/)) return { ok: false, error: 'invalid section' };
            let c = uci.cursor();
            let stype = c.get('4eburnet', sec);
            if (stype != 'server') return { ok: false, error: 'not a server section' };
            c.delete('4eburnet', sec);
            c.commit('4eburnet');
            return { ok: true, section: sec };
        }
    },

    rules_list: {
        call: function(req) {
            let rules = uci_get_sections_of_type('4eburnet', 'traffic_rule');
            return { rules, source: 'uci' };
        }
    },

    rule_add: {
        args: { type: '', value: '', target: '', priority: 0 },
        call: function(req) {
            let a = req.args ?? {};
            let valid = { domain:1, domain_suffix:1, domain_keyword:1,
                          ip_cidr:1, geoip:1, geosite:1, rule_set:1, match:1 };
            if (!valid[a.type]) return { ok: false, error: 'invalid rule type' };

            let priority = int(a.priority ?? 500);
            if (!priority || priority < 1 || priority > 9999)
                return { ok: false, error: 'priority must be 1-9999' };

            let c = uci.cursor();
            let sec = c.add('4eburnet', 'traffic_rule');
            c.set('4eburnet', sec, 'type',     a.type);
            c.set('4eburnet', sec, 'value',    '' + (a.value ?? ''));
            c.set('4eburnet', sec, 'target',   '' + (a.target ?? 'DIRECT'));
            c.set('4eburnet', sec, 'priority', '' + priority);
            c.commit('4eburnet');

            return { ok: true, section: sec };
        }
    },

    rule_delete: {
        args: { section: '' },
        call: function(req) {
            let sec = req.args?.section ?? '';
            if (match(sec, /[^\w\-]/)) return { ok: false, error: 'invalid section' };
            let c = uci.cursor();
            let stype = c.get('4eburnet', sec);
            if (stype != 'traffic_rule') return { ok: false, error: 'not a traffic_rule' };
            c.delete('4eburnet', sec);
            c.commit('4eburnet');
            return { ok: true };
        }
    },

    groups: {
        call: function(req) {
            if (!is_running()) return { error: 'not running', groups: [] };
            let d = ipc_json('groups');
            if (d.error) return { error: d.error, groups: [] };
            return d;
        }
    },

    group_select: {
        args: { group: '', server: '' },
        call: function(req) {
            if (!is_running()) return { ok: false, error: 'not running' };
            let group  = req.args?.group  ?? '';
            let server = req.args?.server ?? '';
            if (!group || !server)
                return { ok: false, error: 'group and server required' };
            let r = ipc_json('group-select',
                        json({ group: group, server: server }));
            return r.error ? { ok: false, error: r.error }
                           : { ok: r.status === 'ok' };
        }
    },

    providers: {
        call: function(req) {
            if (!is_running()) return { error: 'not running', providers: [] };
            let d = ipc_json('providers');
            if (d.error) return { error: d.error, providers: [] };
            return d;
        }
    },

    provider_update: {
        args: { name: '' },
        call: function(req) {
            if (!is_running()) return { ok: false, error: 'not running' };
            let name = req.args?.name ?? '';
            if (!name) return { ok: false, error: 'name required' };
            let r = ipc_json('provider-update',
                        json({ name: name }));
            return r.error ? { ok: false, error: r.error }
                           : { ok: r.status === 'ok' };
        }
    },

    geo_status: {
        call: function(req) {
            if (!is_running()) {
                let f = fs.open('/etc/4eburnet/geo/geoip.dat', 'r');
                let loaded = (f != null);
                if (f) f.close();
                return { loaded, categories: [] };
            }
            let d = ipc_json('geo-status');
            if (d.error) return { loaded: false, categories: [], error: d.error };
            return d;
        }
    },

    dpi_get: {
        call: function(req) {
            let main = uci_get_section('4eburnet', 'main');
            let dpi_dir = main.dpi_dir ?? '/etc/4eburnet/dpi';

            // Статистика из файлов на диске
            let ipset_lines     = count_lines(dpi_dir + '/ipset.txt');
            let whitelist_count = count_lines(dpi_dir + '/whitelist.txt');
            let autohosts_count = count_lines(dpi_dir + '/autohosts.txt');

            // Timestamp последнего обновления CDN IP
            let stamp = 0;
            let sf = fs.open(dpi_dir + '/ipset.stamp', 'r');
            if (sf) {
                stamp = int(sf.read('line')) ?? 0;
                sf.close();
            }

            return {
                dpi_enabled:              main.dpi_enabled              ?? '0',
                dpi_split_pos:            main.dpi_split_pos            ?? '1',
                dpi_fake_ttl:             main.dpi_fake_ttl             ?? '5',
                dpi_fake_repeats:         main.dpi_fake_repeats         ?? '8',
                dpi_fake_sni:             main.dpi_fake_sni             ?? 'www.google.com',
                dpi_dir:                  dpi_dir,
                cdn_update_interval_days: main.cdn_update_interval_days ?? '7',
                cdn_cf_v4_url:            main.cdn_cf_v4_url            ?? '',
                cdn_cf_v6_url:            main.cdn_cf_v6_url            ?? '',
                cdn_fastly_url:           main.cdn_fastly_url           ?? '',
                ipset_lines,
                whitelist_count,
                autohosts_count,
                ipset_updated:            stamp > 0 ? stamp : null
            };
        }
    },

    dpi_set: {
        args: {},
        call: function(req) {
            let a = req.args ?? {};
            let allowed = {
                dpi_enabled:1, dpi_split_pos:1, dpi_fake_ttl:1,
                dpi_fake_repeats:1, dpi_fake_sni:1, dpi_dir:1,
                cdn_update_interval_days:1, cdn_cf_v4_url:1,
                cdn_cf_v6_url:1, cdn_fastly_url:1
            };
            let c = uci.cursor();
            let updated = [];
            for (let k in a) {
                if (!allowed[k]) continue;
                let val = '' + a[k];
                /* dpi_dir: абсолютный путь, без '..' */
                if (k === 'dpi_dir') {
                    if (length(val) < 2 || val[0] !== '/' || index(val, '..') >= 0)
                        continue;
                }
                c.set('4eburnet', 'main', k, val);
                push(updated, k);
            }
            c.commit('4eburnet');
            return { ok: true, updated };
        }
    },

    cdn_update: {
        call: function(req) {
            if (!is_running()) return { ok: false, error: 'daemon not running' };
            let r = ipc_json('cdn-update');
            if (r.error) return { ok: false, error: r.error };
            return { ok: true, msg: r.msg ?? 'cdn update scheduled' };
        }
    },

    dns_get: {
        call: function(req) {
            return uci_get_section('4eburnet', 'dns');
        }
    },

    dns_set: {
        args: {},
        call: function(req) {
            let a = req.args ?? {};
            let allowed = {
                upstream_bypass:1, upstream_proxy:1, upstream_default:1,
                upstream_fallback:1, upstream_port:1, cache_size:1,
                parallel_query:1, doh_enabled:1, doh_url:1, doh_ip:1,
                doh_sni:1, doh_port:1, dot_enabled:1, dot_server_ip:1,
                dot_port:1, dot_sni:1, doq_enabled:1, doq_server_ip:1,
                doq_server_port:1, doq_sni:1, fake_ip_enabled:1,
                fake_ip_range:1, fake_ip_ttl:1, fake_ip_pool_size:1,
                bogus_nxdomain:1
            };
            let c = uci.cursor();
            let updated = [];
            for (let k in a) {
                if (allowed[k]) {
                    c.set('4eburnet', 'dns', k, '' + a[k]);
                    push(updated, k);
                }
            }
            c.commit('4eburnet');
            return { ok: true, updated };
        }
    },

    config_get: {
        args: { section: '' },
        call: function(req) {
            let section = req.args?.section ?? 'main';
            if (match(section, /[^\w]/)) return { error: 'invalid section' };
            return uci_get_section('4eburnet', section);
        }
    },

    config_set: {
        args: { section: '', values: {} },
        call: function(req) {
            let section = req.args?.section ?? 'main';
            let values  = req.args?.values  ?? {};
            if (match(section, /[^\w]/)) return { ok: false, error: 'invalid section' };

            let allowed = {
                main: { enabled:1, mode:1, log_level:1, lan_interface:1, region:1, geo_dir:1, geo_url:1 },
                dns:  { upstream_bypass:1, upstream_proxy:1, doh_enabled:1, doh_url:1,
                        doh_ip:1, fake_ip_enabled:1, bogus_nxdomain:1 }
            };
            let sec_allowed = allowed[section];
            if (!sec_allowed) return { ok: false, error: 'section not editable: ' + section };

            let c = uci.cursor();
            let updated = [];
            for (let k in values) {
                if (sec_allowed[k]) {
                    c.set('4eburnet', section, k, '' + values[k]);
                    push(updated, k);
                }
            }
            c.commit('4eburnet');
            return { ok: true, updated };
        }
    },

    adblock_status: {
        call: function(req) {
            let dns = uci_get_section('4eburnet', 'dns');
            let enabled = (dns['fake_ip_enabled'] == '1');
            let ads = file_lines('/etc/4eburnet/geo/geosite-ads.lst');
            return {
                enabled,
                ads_count: length(ads),
                geo_file:  '/etc/4eburnet/geo/geosite-ads.lst',
                has_list:  length(ads) > 0
            };
        }
    },

    backup_status: {
        call: function(req) {
            let f = fs.open(BACKUP_FILE, 'r');
            if (!f) return { exists: false, path: BACKUP_FILE };
            let size = f.seek(0, 2) ?? 0;
            f.close();
            return { exists: true, path: BACKUP_FILE, size };
        }
    },

    backup: {
        call: function(req) {
            system('mkdir -p /etc/4eburnet 2>/dev/null');
            let files = [];
            let backup_paths = ['/etc/config/4eburnet', '/etc/4eburnet/geo'];
            for (let i = 0; i < length(backup_paths); i++) {
                let p = backup_paths[i];
                let f = fs.open(p, 'r');
                if (f) { f.close(); push(files, p); }
            }
            if (!length(files)) return { ok: false, error: 'no files to backup' };
            let ret = system('tar czf ' + BACKUP_FILE + ' ' + join(' ', files) + ' 2>/dev/null');
            let ok = ret == 0;
            let size = 0;
            if (ok) {
                let f = fs.open(BACKUP_FILE, 'r');
                if (f) { size = f.seek(0, 2) ?? 0; f.close(); }
            }
            return {
                ok: ok && size > 0,
                path: BACKUP_FILE,
                size,
                message: (ok && size > 0) ? 'backup created (' + int(size/1024) + 'KB)' : 'backup failed'
            };
        }
    },

    restore: {
        args: { path: '' },
        call: function(req) {
            let path = req.args?.path ?? BACKUP_FILE;
            let allowed = { [BACKUP_FILE]: 1, '/tmp/4eburnet-backup.tar.gz': 1, '/tmp/4eburnet-restore.tar.gz': 1 };
            if (!allowed[path]) return { ok: false, error: 'restore only allowed from known paths' };
            let f = fs.open(path, 'r');
            if (!f) return { ok: false, error: 'file not found: ' + path };
            f.close();
            let ret = system('tar xzf ' + path + ' -C / 2>/dev/null');
            let ok = ret == 0;
            return { ok, message: ok ? 'restored' : 'failed' };
        }
    },

    subscription_import: {
        args: { url: '', content: '', format: 'auto',
                no_rules: false, no_groups: false, max_rules: 256 },
        call: function(req) {
            let url       = req.args?.url       ?? '';
            let content   = req.args?.content   ?? '';
            let fmt       = req.args?.format    ?? 'auto';
            let no_rules  = req.args?.no_rules  ? '--no-rules'  : '';
            let no_groups = req.args?.no_groups ? '--no-groups' : '';
            let max_rules = int(req.args?.max_rules ?? 256);

            if (!url && !content)
                return { ok: false, error: 'url or content required' };

            let sub_py = '/usr/share/4eburnet/sub_convert.py';
            if (!fs.access(sub_py, 'r'))
                return { ok: false, error: 'sub_convert.py not found' };

            let rnd = time() + '-' + math.floor(math.random() * 0xFFFFFF);
            let tmp_in  = '/tmp/.4eburnet-sub-' + rnd + '-in.tmp';
            let tmp_out = '/tmp/.4eburnet-sub-' + rnd + '-out.uci';
            let tmp_err = '/tmp/.4eburnet-sub-' + rnd + '-err.log';

            /* Записать content во временный файл если передан напрямую */
            if (content) {
                let f = fs.open(tmp_in, 'w');
                if (!f) return { ok: false, error: 'cannot write tmp file' };
                f.write(content);
                f.close();
                fs.chmod(tmp_in, 0o600);
            }

            /* Валидация fmt по allowlist — подстановка в shell без кавычек */
            let allowed_fmts = ['auto', 'clash', 'base64', 'urilist', 'singbox'];
            let safe_fmt = 'auto';
            for (let i = 0; i < length(allowed_fmts); i++) {
                if (fmt === allowed_fmts[i]) { safe_fmt = fmt; break; }
            }

            /* Экранирование строки для shell single-quote: ' → '\'' */
            function sh_quote(s) {
                let parts = split('' + s, "'");
                return "'" + join("'\\''", parts) + "'";
            }

            let input_arg = url
                ? ('--url '  + sh_quote(url))
                : ('-i '     + sh_quote(tmp_in));

            /* safe_fmt из allowlist — безопасен без кавычек */
            let cmd = 'python3 ' + sh_quote(sub_py) + ' '
                    + input_arg                      + ' '
                    + '--format '    + safe_fmt       + ' '
                    + '--output '    + sh_quote(tmp_out) + ' '
                    + '--max-rules ' + int(max_rules) + ' '
                    + (no_rules  ? '--no-rules '  : '')
                    + (no_groups ? '--no-groups ' : '')
                    + '2>' + sh_quote(tmp_err);

            let rc = system(cmd);
            if (content) fs.unlink(tmp_in);

            /* Прочитать лог для статистики и диагностики */
            let log = '';
            let ef = fs.open(tmp_err, 'r');
            if (ef) { log = ef.read('all'); ef.close(); }

            if (rc !== 0) {
                fs.unlink(tmp_out);
                fs.unlink(tmp_err);
                return { ok: false, error: trim(log) || 'convert failed' };
            }

            /* Валидировать UCI файл: только допустимые типы секций */
            let allowed_types = {
                server: true, proxy_group: true,
                traffic_rule: true, dns_rule: true, device: true
            };
            let uci_valid = true;
            let uci_f = fs.open(tmp_out, 'r');
            if (uci_f) {
                let ln;
                while ((ln = uci_f.read('line')) !== null) {
                    let tm = match(trim(ln), /^config\s+(\S+)/);
                    if (tm && !allowed_types[tm[1]]) {
                        uci_valid = false;
                        break;
                    }
                }
                uci_f.close();
            }
            if (!uci_valid) {
                fs.unlink(tmp_out);
                fs.unlink(tmp_err);
                return { ok: false, error: 'UCI файл содержит недопустимые типы секций' };
            }

            /* Применить UCI (merge — не перезаписываем существующий конфиг) */
            rc = system('uci import -m 4eburnet < ' + sh_quote(tmp_out)
                        + ' && uci commit 4eburnet 2>>' + sh_quote(tmp_err));
            fs.unlink(tmp_out);

            /* Извлечь статистику из лога конвертера */
            let m = match(log, /Серверов:\s+(\d+)/);
            let servers = m ? int(m[1]) : 0;
            m = match(log, /Групп:\s+(\d+)/);
            let grps = m ? int(m[1]) : 0;
            m = match(log, /Правил:\s+(\d+)/);
            let rules = m ? int(m[1]) : 0;

            fs.unlink(tmp_err);

            if (rc !== 0)
                return { ok: false, error: 'uci import failed' };

            /* Reload демона если запущен */
            if (is_running())
                ipc_json('reload');

            return {
                ok:      true,
                servers: servers,
                groups:  grps,
                rules:   rules,
                message: 'импортировано: ' + servers + ' серверов, '
                         + grps + ' групп, ' + rules + ' правил'
            };
        }
    }
};

return { '4eburnet': methods };
