#!/usr/bin/ucode
'use strict';

import * as fs   from 'fs';
import * as uci  from 'uci';

// ── Константы ──────────────────────────────────────────────────────
const SOCKET      = '/var/run/4eburnet.sock';
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

// ── IPC (заглушка — демон ещё не запущен) ──────────────────────────
function ipc_call(cmd, payload) {
    // TODO: реализовать Unix socket IPC к 4eburnetd
    // Пока возвращает ошибку если демон не запущен
    return { error: 'daemon not running' };
}

// ── Методы ─────────────────────────────────────────────────────────

const methods = {

    status: {
        call: function(req) {
            let running = is_running();
            return {
                running:   running,
                uptime:    0,
                mode:      uci_get_section('4eburnet', 'main')['mode'] ?? 'rules',
                profile:   'unknown',
                timestamp: time()
            };
        }
    },

    stats: {
        call: function(req) {
            if (!is_running())
                return { error: 'not running', connections: 0,
                         dns_queries: 0, dns_cached: 0, connections_total: 0 };
            return ipc_call(4);
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
            system('/etc/init.d/4eburnet stop 2>/dev/null');
            system('sleep 1');
            let ret = system('/etc/init.d/4eburnet start 2>/dev/null');
            return { ok: ret == 0 };
        }
    },

    tproxy_status: {
        call: function(req) {
            let f = fs.open('/sys/module/nft_tproxy/refcnt', 'r');
            let avail = (f != null);
            if (f) f.close();
            return { available: avail };
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
                        let _tmp0 = devs;
                        for (let i = 0; i < length(_tmp0); i++) {
                            let d = _tmp0[i];
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
            let _tmp1 = devs;
            for (let i = 0; i < length(_tmp1); i++) {
                let d = _tmp1[i];
                d.policy = 'default';
                let _tmp2 = policies;
                for (let j = 0; j < length(_tmp2); j++) {
                    let ps = _tmp2[j];
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
            let _tmp3 = uci_get_sections_of_type('4eburnet', 'device');
            for (let i = 0; i < length(_tmp3); i++) {
                let s = _tmp3[i];
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
                reality_pbk: '', reality_sid: '' },
        call: function(req) {
            let a = req.args ?? {};
            let _tmp4 = ['name', 'protocol', 'address', 'port'];
            for (let i = 0; i < length(_tmp4); i++) {
                let f = _tmp4[i];
                if (!a[f]) return { ok: false, error: 'field required: ' + f };
            }

            let proto_ok = { vless: 1, trojan: 1, shadowsocks: 1, awg: 1 };
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
                         xhttp_path:1, xhttp_host:1 };
            for (let k in a)
                if (safe[k] && a[k]) c.set('4eburnet', sec, k, '' + a[k]);
            c.set('4eburnet', sec, 'port', '' + port);
            c.set('4eburnet', sec, 'enabled', '1');
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
            return ipc_call(20);
        }
    },

    group_select: {
        args: { group: '', idx: 0 },
        call: function(req) {
            if (!is_running()) return { ok: false, error: 'not running' };
            return { ok: true };
        }
    },

    providers: {
        call: function(req) {
            if (!is_running()) return { error: 'not running', providers: [] };
            return ipc_call(23);
        }
    },

    provider_update: {
        args: { name: '' },
        call: function(req) {
            return { ok: false, error: 'not running' };
        }
    },

    geo_status: {
        call: function(req) {
            let f = fs.open('/etc/4eburnet/geo/geoip.dat', 'r');
            let loaded = (f != null);
            if (f) f.close();
            return { loaded };
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
                main: { enabled:1, mode:1, log_level:1, lan_interface:1, region:1, geo_dir:1 },
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
            let _tmp5 = ['/etc/config/4eburnet', '/etc/4eburnet/geo'];
            for (let i = 0; i < length(_tmp5); i++) {
                let p = _tmp5[i];
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
    }
};

return { '4eburnet': methods };
