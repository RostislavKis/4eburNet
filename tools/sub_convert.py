#!/usr/bin/env python3
"""
4eburNet Subscription Converter
Конвертирует подписки в UCI формат /etc/config/4eburnet

Поддерживаемые форматы входа:
  - Clash/Mihomo YAML (proxies: + proxy-groups: + rules:)
  - base64 URI список (vless:// ss:// trojan:// hysteria2://)
  - sing-box JSON (outbounds: + route.rules:)

Использование:
  python3 sub_convert.py -i sub.yaml -o /etc/config/4eburnet
  python3 sub_convert.py -i sub.b64 --format base64
  python3 sub_convert.py -i config.json --format singbox
  python3 sub_convert.py --url https://sub.example.com/sub --token TOKEN
"""

import sys
import os
import re
import ssl
import base64
import json
import argparse
import urllib.request
import urllib.parse
from urllib.error import URLError, HTTPError

try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# ── URI парсеры ────────────────────────────────────────────────────────

def parse_vless_uri(uri: str) -> dict | None:
    """vless://UUID@host:port?params#name"""
    m = re.match(
        r'^vless://([^@]+)@([^:@]+):(\d+)([^#]*)(?:#(.*))?$', uri)
    if not m:
        return None
    uuid, host, port, query_str, name = m.groups()
    params = {}
    if query_str:
        for kv in query_str.lstrip('?').split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
                params[k] = urllib.parse.unquote(v)
    return {
        'protocol':    'vless',
        'name':        urllib.parse.unquote(name or host),
        'address':     host,
        'port':        int(port),
        'uuid':        uuid,
        'transport':   params.get('type', 'raw'),
        'reality_pbk': params.get('pbk', ''),
        'reality_sid': params.get('sid', ''),
        'xhttp_path':  params.get('path', ''),
        'xhttp_host':  params.get('host', ''),
        'sni':         params.get('sni', ''),
        'fp':          params.get('fp', ''),
    }


def parse_ss_uri(uri: str) -> dict | None:
    """ss://base64(method:password)@host:port#name
       или ss://base64(method:password@host:port)#name"""
    try:
        no_prefix = uri[5:]  # убрать 'ss://'
        name = ''
        if '#' in no_prefix:
            no_prefix, name = no_prefix.rsplit('#', 1)
            name = urllib.parse.unquote(name)

        # Формат 1: base64@host:port
        if '@' in no_prefix:
            b64_part, hostport = no_prefix.rsplit('@', 1)
            # Добавить padding
            b64_part += '=' * (-len(b64_part) % 4)
            decoded = base64.b64decode(b64_part).decode('utf-8')
            method, password = decoded.split(':', 1)
            if ':' in hostport:
                host, port = hostport.rsplit(':', 1)
            else:
                return None
        else:
            # Формат 2: base64(method:password@host:port)
            b64 = no_prefix + '=' * (-len(no_prefix) % 4)
            decoded = base64.b64decode(b64).decode('utf-8')
            m = re.match(r'^([^:]+):(.+)@([^:]+):(\d+)$', decoded)
            if not m:
                return None
            method, password, host, port = m.groups()

        return {
            'protocol': 'shadowsocks',
            'name':     name or host,
            'address':  host,
            'port':     int(port),
            'password': password,
        }
    except Exception:
        return None


def parse_trojan_uri(uri: str) -> dict | None:
    """trojan://password@host:port?params#name"""
    m = re.match(
        r'^trojan://([^@]+)@([^:@]+):(\d+)([^#]*)(?:#(.*))?$', uri)
    if not m:
        return None
    password, host, port, query_str, name = m.groups()
    params = {}
    if query_str:
        for kv in query_str.lstrip('?').split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
                params[k] = urllib.parse.unquote(v)
    srv = {
        'protocol': 'trojan',
        'name':     urllib.parse.unquote(name or host),
        'address':  host,
        'port':     int(port),
        'password': password,
        'sni':      params.get('sni', ''),
    }
    # ShadowTLS из URI: ?transport=shadowtls&stls-password=X&stls-sni=Y
    if params.get('transport') == 'shadowtls':
        stls_pass = params.get('stls-password', params.get('shadow-tls-password', ''))
        stls_sni  = params.get('stls-sni', params.get('shadow-tls-sni', ''))
        if stls_pass:
            srv['transport']     = 'shadowtls'
            srv['stls_password'] = stls_pass
            srv['stls_sni']      = stls_sni or host
    return srv


def parse_hysteria2_uri(uri: str) -> dict | None:
    """hysteria2://password@host:port?params#name
       hy2://password@host:port?params#name"""
    uri_norm = uri.replace('hy2://', 'hysteria2://', 1)
    m = re.match(
        r'^hysteria2://([^@]+)@([^:@]+):(\d+)([^#]*)(?:#(.*))?$', uri_norm)
    if not m:
        return None
    password, host, port, query_str, name = m.groups()
    params = {}
    if query_str:
        for kv in query_str.lstrip('?').split('&'):
            if '=' in kv:
                k, v = kv.split('=', 1)
                params[k] = urllib.parse.unquote(v)
    return {
        'protocol':  'hysteria2',
        'name':      urllib.parse.unquote(name or host),
        'address':   host,
        'port':      int(port),
        'password':  password,
        'sni':       params.get('sni', ''),
        'insecure':  params.get('insecure', '0'),
        'obfs':      params.get('obfs', ''),
        'obfs_pass': params.get('obfs-password', ''),
        'up_mbps':   params.get('up', '100'),
        'down_mbps': params.get('down', '100'),
    }


def parse_uri(uri: str) -> dict | None:
    """Определить формат URI и распарсить."""
    uri = uri.strip()
    if uri.startswith('vless://'):
        return parse_vless_uri(uri)
    if uri.startswith('ss://'):
        return parse_ss_uri(uri)
    if uri.startswith('trojan://'):
        return parse_trojan_uri(uri)
    if uri.startswith('hysteria2://') or uri.startswith('hy2://'):
        return parse_hysteria2_uri(uri)
    return None


# ── Форматы входа ──────────────────────────────────────────────────────

def parse_base64_subscription(data: str,
                               max_servers: int = 500) -> list:
    """base64 строка содержащая список URI (один на строку)."""
    servers = []
    # Попробовать декодировать base64
    try:
        # Нормализовать: убрать пробелы, добавить padding
        clean = data.strip().replace('\n', '').replace('\r', '').replace(' ', '')
        padded = clean + '=' * (-len(clean) % 4)
        decoded = base64.b64decode(padded).decode('utf-8')
    except Exception:
        # Не base64 — попробовать как plain URI список
        decoded = data

    for line in decoded.splitlines():
        if len(servers) >= max_servers:
            print(f'  [truncate] серверов > {max_servers}, усечено',
                  file=sys.stderr)
            break
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        server = parse_uri(line)
        if server:
            servers.append(server)
        else:
            print(f'  [skip] неизвестный URI: {line[:60]}', file=sys.stderr)

    return servers


def _parse_clash_yaml_native(doc: dict, max_servers: int = 500) -> tuple:
    """Парсить Clash YAML через PyYAML dict (anchors развёрнуты)."""
    servers, providers, groups, rules = [], [], [], []

    # proxies → servers
    for p in (doc.get('proxies') or [])[:max_servers]:
        _clash_proxy_to_server(p, servers)

    # proxy-providers → UCI proxy_provider секции
    for name, pd in (doc.get('proxy-providers') or {}).items():
        if not isinstance(pd, dict):
            continue
        hc = pd.get('health-check') or {}
        providers.append({
            'name':            name,
            'url':             pd.get('url', ''),
            'interval':        str(pd.get('interval', 3600)),
            'health_url':      hc.get('url', ''),
            'health_interval': str(hc.get('interval', 300)),
            'enabled':         '1',
        })

    # proxy-groups
    for g in (doc.get('proxy-groups') or []):
        if not isinstance(g, dict) or not g.get('name'):
            continue
        grp = {
            'name':    g.get('name', ''),
            'type':    g.get('type', 'select').replace('-', '_'),
            'enabled': '1',
        }
        if g.get('proxies'):
            grp['proxies'] = [str(x) for x in g['proxies']]
        if g.get('use'):
            grp['providers'] = ' '.join(str(x) for x in g['use'])
        if g.get('url'):
            grp['url'] = str(g['url'])
        if g.get('interval'):
            grp['interval'] = str(g['interval'])
        if g.get('filter'):
            grp['filter'] = str(g['filter'])
        groups.append(grp)

    # rules
    for r in (doc.get('rules') or []):
        parsed = _parse_clash_rule(str(r))
        if parsed:
            rules.append(parsed)

    return servers, providers, groups, rules


def parse_clash_yaml(data: str, max_servers: int = 500) -> tuple:
    """Парсить Clash/Mihomo YAML.
    Возвращает (servers, providers, groups, rules).
    PyYAML если доступен (разворачивает anchors), иначе построчный fallback."""

    # PyYAML: разворачивает anchors, proxy-providers, use:
    if HAS_YAML:
        try:
            doc = _yaml.safe_load(data)
            if isinstance(doc, dict) and (
                    'proxies' in doc or 'proxy-groups' in doc or
                    'proxy-providers' in doc):
                return _parse_clash_yaml_native(doc, max_servers)
        except Exception as e:
            print(f'  [warn] PyYAML: {e}, fallback на построчный',
                  file=sys.stderr)

    # Fallback: построчный парсер (без anchors/providers)
    servers = []
    groups  = []
    rules   = []

    in_proxies = False
    in_groups  = False
    in_rules   = False
    current    = None

    for line in data.splitlines():
        stripped = line.strip()

        # Определить текущую секцию — сначала сбросить незавершённый current
        if stripped == 'proxies:':
            if in_proxies and current:
                _clash_proxy_to_server(current, servers)
            elif in_groups and current:
                groups.append(current)
            in_proxies, in_groups, in_rules = True, False, False
            current = None
            continue
        if stripped == 'proxy-groups:':
            if in_proxies and current:
                _clash_proxy_to_server(current, servers)
            elif in_groups and current:
                groups.append(current)
            in_proxies, in_groups, in_rules = False, True, False
            current = None
            continue
        if stripped == 'rules:':
            if in_proxies and current:
                _clash_proxy_to_server(current, servers)
            elif in_groups and current:
                groups.append(current)
            in_proxies, in_groups, in_rules = False, False, True
            current = None
            continue
        # Любой другой top-level ключ без отступа
        if line and line[0] not in (' ', '\t', '-') and ':' in line:
            if in_proxies and current:
                _clash_proxy_to_server(current, servers)
            elif in_groups and current:
                groups.append(current)
            in_proxies, in_groups, in_rules = False, False, False
            current = None

        # Парсинг proxies
        if in_proxies:
            if stripped.startswith('- name:'):
                if current:
                    _clash_proxy_to_server(current, servers)
                # Early stop при достижении лимита
                if len(servers) >= max_servers:
                    print(f'  [truncate] серверов > {max_servers}, усечено',
                          file=sys.stderr)
                    current = None
                    break
                current = {'name': stripped[7:].strip().strip('"').strip("'")}
            elif stripped.startswith('- {'):
                if current:
                    _clash_proxy_to_server(current, servers)
                current = _parse_inline_dict(stripped[2:])
            elif current and ':' in stripped and not stripped.startswith('#'):
                k, _, v = stripped.partition(':')
                current[k.strip()] = v.strip().strip('"').strip("'")

        # Парсинг proxy-groups
        elif in_groups:
            if stripped.startswith('- name:'):
                if current:
                    groups.append(current)
                current = {
                    'name': stripped[7:].strip().strip('"').strip("'"),
                    'proxies': []
                }
            elif current:
                if stripped.startswith('type:'):
                    current['type'] = stripped[5:].strip()
                elif stripped.startswith('url:'):
                    current['url'] = stripped[4:].strip()
                elif stripped.startswith('interval:'):
                    current['interval'] = stripped[9:].strip()
                elif stripped.startswith('- ') and 'type' in current:
                    current.setdefault('proxies', []).append(
                        stripped[2:].strip().strip('"').strip("'"))

        # Парсинг rules
        elif in_rules:
            if stripped.startswith('- ') and not stripped.startswith('- name:'):
                rule_str = stripped[2:].strip()
                rule = _parse_clash_rule(rule_str)
                if rule:
                    rules.append(rule)

    # Добавить последние элементы
    if in_proxies and current:
        _clash_proxy_to_server(current, servers)
    if in_groups and current:
        groups.append(current)

    return servers, [], groups, rules


def _parse_inline_dict(s: str) -> dict:
    """Парсить inline YAML dict: {key: val, key: val}"""
    result = {}
    s = s.strip().strip('{}')
    for part in re.split(r',\s*(?=[a-zA-Z_-]+:)', s):
        if ':' in part:
            k, _, v = part.partition(':')
            result[k.strip()] = v.strip().strip('"').strip("'")
    return result


def _apply_shadowtls(proxy: dict, srv: dict) -> None:
    """Извлечь ShadowTLS параметры из Clash proxy dict.
    Два формата:
      1) shadow-tls-password + shadow-tls-sni (inline)
      2) plugin: shadow-tls + plugin-opts: {password, host}
    """
    stls_pass = proxy.get('shadow-tls-password', '')
    stls_sni  = proxy.get('shadow-tls-sni', '')

    # Формат plugin-opts
    if not stls_pass:
        plugin = proxy.get('plugin', '')
        if plugin == 'shadow-tls':
            opts = proxy.get('plugin-opts', {})
            if isinstance(opts, dict):
                stls_pass = opts.get('password', '')
                stls_sni  = opts.get('host', '')

    if stls_pass:
        srv['transport']     = 'shadowtls'
        srv['stls_password'] = stls_pass
        srv['stls_sni']      = stls_sni or srv.get('address', '')


def _clash_proxy_to_server(proxy: dict, servers: list) -> None:
    """Конвертировать Clash proxy dict в 4eburNet server dict."""
    ptype = proxy.get('type', '').lower()
    name  = proxy.get('name', '')
    host  = proxy.get('server', '')
    port  = proxy.get('port', 443)

    if not host:
        return

    if ptype == 'vless':
        servers.append({
            'protocol':    'vless',
            'name':        name,
            'address':     host,
            'port':        int(port),
            'uuid':        proxy.get('uuid', ''),
            'transport':   proxy.get('network', 'raw'),
            'reality_pbk': proxy.get('reality-opts', {}).get('public-key', '')
                           if isinstance(proxy.get('reality-opts'), dict)
                           else proxy.get('pbk', ''),
            'reality_sid': proxy.get('reality-opts', {}).get('short-id', '')
                           if isinstance(proxy.get('reality-opts'), dict)
                           else proxy.get('sid', ''),
            'sni':         proxy.get('servername', proxy.get('sni', '')),
        })
    elif ptype == 'trojan':
        srv = {
            'protocol': 'trojan',
            'name':     name,
            'address':  host,
            'port':     int(port),
            'password': proxy.get('password', ''),
            'sni':      proxy.get('sni', ''),
        }
        _apply_shadowtls(proxy, srv)
        servers.append(srv)
    elif ptype in ('ss', 'shadowsocks'):
        srv = {
            'protocol': 'shadowsocks',
            'name':     name,
            'address':  host,
            'port':     int(port),
            'password': proxy.get('password', ''),
        }
        _apply_shadowtls(proxy, srv)
        servers.append(srv)
    elif ptype == 'hysteria2':
        servers.append({
            'protocol':  'hysteria2',
            'name':      name,
            'address':   host,
            'port':      int(port),
            'password':  proxy.get('password', ''),
            'sni':       proxy.get('sni', ''),
            'up_mbps':   str(proxy.get('up', '100')),
            'down_mbps': str(proxy.get('down', '100')),
        })
    elif ptype == 'wireguard':
        srv = {
            'protocol':    'awg',
            'name':        name,
            'address':     host,
            'port':        int(port),
            'private_key': proxy.get('private-key', ''),
            'public_key':  proxy.get('public-key', ''),
        }
        # AWG obfuscation: из amnezia-wg-option dict или top-level
        awg_opts = proxy.get('amnezia-wg-option') or proxy
        # jc/jmin/jmax
        for src_key, dst_key in [('jc', 'awg_jc'), ('Jc', 'awg_jc'),
                                  ('jmin', 'awg_jmin'), ('Jmin', 'awg_jmin'),
                                  ('jmax', 'awg_jmax'), ('Jmax', 'awg_jmax')]:
            if src_key in awg_opts:
                srv[dst_key] = str(awg_opts[src_key])
        # s1-s4, h1-h4
        for src, dst in [('s1','awg_s1'),('s2','awg_s2'),('s3','awg_s3'),('s4','awg_s4'),
                          ('h1','awg_h1'),('h2','awg_h2'),('h3','awg_h3'),('h4','awg_h4')]:
            if src in awg_opts:
                srv[dst] = str(awg_opts[src])
        # i1-i5 (hex blob строки)
        for n in range(1, 6):
            key = f'i{n}'
            if key in awg_opts and awg_opts[key]:
                srv[f'awg_i{n}'] = str(awg_opts[key])
        servers.append(srv)
    else:
        print(f'  [skip] неподдерживаемый тип: {ptype} ({name})',
              file=sys.stderr)


def _parse_clash_rule(rule_str: str) -> dict | None:
    """Парсить строку правила Clash: TYPE,value,TARGET или TYPE,TARGET"""
    parts = rule_str.split(',')
    if len(parts) < 2:
        return None

    rtype = parts[0].strip().upper()
    type_map = {
        'DOMAIN':         'domain',
        'DOMAIN-SUFFIX':  'domain_suffix',
        'DOMAIN-KEYWORD': 'domain_keyword',
        'IP-CIDR':        'ip_cidr',
        'IP-CIDR6':       'ip_cidr',
        'GEOIP':          'geoip',
        'GEOSITE':        'geosite',
        'RULE-SET':       'rule_set',
        'MATCH':          'match',
        'DST-PORT':       'port',
        'SRC-PORT':       None,
        'PROCESS-NAME':   None,
        'OR':             None,
        'NOT':            None,
    }

    # AND,((NETWORK,proto),(DST-PORT,port)),target → type=port
    if rtype == 'AND':
        m = re.match(
            r'\(\(NETWORK,[^)]+\),\(DST-PORT,([^)]+)\)\),(.+)',
            ','.join(parts[1:]))
        if m:
            return {'type': 'port', 'value': m.group(1).strip(),
                    'target': m.group(2).strip()}
        return None

    uci_type = type_map.get(rtype)
    if uci_type is None:
        return None

    if rtype == 'MATCH':
        target = parts[1].strip()
        value  = ''
    elif len(parts) >= 3:
        value  = parts[1].strip()
        target = parts[2].strip()
    else:
        return None

    target = target.strip()
    if not target:
        return None

    return {
        'type':   uci_type,
        'value':  value,
        'target': target,
    }


def parse_singbox_json(data: str, max_servers: int = 500) -> tuple:
    """Парсить sing-box JSON. Возвращает (servers, rules)."""
    servers = []
    rules   = []

    try:
        cfg = json.loads(data)
    except json.JSONDecodeError as e:
        print(f'Ошибка парсинга JSON: {e}', file=sys.stderr)
        return servers, rules

    for ob in cfg.get('outbounds', []):
        if len(servers) >= max_servers:
            print(f'  [truncate] серверов > {max_servers}, усечено',
                  file=sys.stderr)
            break
        ob_type = ob.get('type', '')
        if ob_type in ('direct', 'block', 'dns', 'selector',
                       'urltest', 'fallback', 'loadbalance'):
            continue

        name = ob.get('tag', ob.get('type', 'unknown'))
        host = ob.get('server', '')
        port = ob.get('server_port', 443)

        if not host:
            continue

        if ob_type == 'vless':
            servers.append({
                'protocol': 'vless',
                'name':     name,
                'address':  host,
                'port':     int(port),
                'uuid':     ob.get('uuid', ''),
                'transport': ob.get('transport', {}).get('type', 'raw')
                             if isinstance(ob.get('transport'), dict)
                             else 'raw',
            })
        elif ob_type == 'trojan':
            servers.append({
                'protocol': 'trojan',
                'name':     name,
                'address':  host,
                'port':     int(port),
                'password': ob.get('password', ''),
            })
        elif ob_type == 'shadowsocks':
            servers.append({
                'protocol': 'shadowsocks',
                'name':     name,
                'address':  host,
                'port':     int(port),
                'password': ob.get('password', ''),
            })
        elif ob_type == 'hysteria2':
            servers.append({
                'protocol':  'hysteria2',
                'name':      name,
                'address':   host,
                'port':      int(port),
                'password':  ob.get('password', ''),
                'up_mbps':   str(ob.get('up_mbps', 100)),
                'down_mbps': str(ob.get('down_mbps', 100)),
            })

    type_map = {
        'domain':         'domain',
        'domain_suffix':  'domain_suffix',
        'domain_keyword': 'domain_keyword',
        'ip_cidr':        'ip_cidr',
        'geoip':          'geoip',
        'geosite':        'geosite',
    }
    for rule in cfg.get('route', {}).get('rules', []):
        outbound = rule.get('outbound', 'DIRECT')
        outbound = re.sub(r'[^\w\-_. ]', '', outbound).strip()
        for sb_key, uci_type in type_map.items():
            values = rule.get(sb_key, [])
            if isinstance(values, str):
                values = [values]
            for v in values:
                rules.append({
                    'type':   uci_type,
                    'value':  v,
                    'target': outbound,
                })

    return servers, rules


# ── Определение формата ────────────────────────────────────────────────

def detect_format(data: str) -> str:
    """Автоопределение формата подписки."""
    stripped = data.strip()

    if stripped.startswith('{') and '"outbounds"' in stripped:
        return 'singbox'

    if stripped.startswith(('vless://', 'ss://', 'trojan://',
                             'hysteria2://', 'hy2://')):
        return 'urilist'

    if re.search(r'^proxies\s*:', stripped, re.MULTILINE):
        return 'clash'

    # Попробовать base64 только для разумного размера
    # Подписки > 2 МБ base64 не бывают — избегаем лишних копий в RAM
    MAX_BASE64_DETECT = 2 * 1024 * 1024
    if len(stripped) <= MAX_BASE64_DETECT:
        try:
            clean = stripped.replace('\n', '').replace(' ', '')
            padded = clean + '=' * (-len(clean) % 4)
            decoded = base64.b64decode(padded).decode('utf-8')
            if any(decoded.strip().startswith(p) for p in
                   ('vless://', 'ss://', 'trojan://', 'hysteria2://')):
                return 'base64'
        except Exception:
            pass

    return 'urilist'


# ── UCI генератор ──────────────────────────────────────────────────────

def _uci_safe(s) -> str:
    """Экранировать строку для UCI значения.

    UCI синтаксис: option key 'value'
    Фильтруем: управляющие символы (<0x20) включая null, CR, tab,
    и одиночные кавычки (закрывают значение в UCI).
    """
    s = str(s)
    s = ''.join(c for c in s if ord(c) >= 0x20 and c != "'")
    return s.strip()


def generate_uci(servers: list,
                 groups:  list,
                 rules:   list,
                 append:  bool = False,
                 providers: list = None) -> str:
    """Генерировать UCI конфиг для серверов, провайдеров, групп и правил."""
    lines = []

    if not append:
        lines.append("# Сгенерировано sub_convert.py")
        lines.append("# Добавьте в /etc/config/4eburnet\n")

    for srv in servers:
        lines.append("config server")
        for key, val in srv.items():
            if val and str(val).strip():
                lines.append(f"\toption {key}\t'{_uci_safe(val)}'")
        lines.append("")

    for prov in (providers or []):
        lines.append("config proxy_provider")
        for key in ('name', 'url', 'interval', 'health_url',
                     'health_interval', 'enabled'):
            val = prov.get(key, '')
            if val:
                lines.append(f"\toption {key}\t'{_uci_safe(str(val))}'")
        lines.append("")

    for grp in groups:
        lines.append("config proxy_group")
        lines.append(f"\toption name\t'{_uci_safe(grp.get('name', ''))}'")
        gtype = grp.get('type', 'url-test').lower().replace('-', '_')
        lines.append(f"\toption type\t'{gtype}'")
        if grp.get('url'):
            lines.append(f"\toption url\t'{_uci_safe(grp['url'])}'")
        if grp.get('interval'):
            lines.append(f"\toption interval\t'{_uci_safe(grp['interval'])}'")
        if grp.get('proxies'):
            if isinstance(grp['proxies'], list):
                for s in grp['proxies']:
                    lines.append(f"\tlist servers\t'{_uci_safe(str(s))}'")
            else:
                val = _uci_safe(str(grp['proxies']))
                lines.append(f"\toption servers\t'{val}'")
        if grp.get('providers'):
            lines.append(f"\toption providers\t'{_uci_safe(str(grp['providers']))}'")
        if grp.get('filter'):
            lines.append(f"\toption filter\t'{_uci_safe(str(grp['filter']))}'")
        lines.append(f"\toption enabled\t'1'")
        lines.append("")

    priority = 200
    for rule in rules:
        lines.append("config traffic_rule")
        lines.append(f"\toption type\t'{rule['type']}'")
        if rule.get('value'):
            lines.append(f"\toption value\t'{_uci_safe(rule['value'])}'")
        lines.append(f"\toption target\t'{_uci_safe(rule['target'])}'")
        lines.append(f"\toption priority\t'{priority}'")
        lines.append("")
        priority += 1

    return '\n'.join(lines)


# ── Загрузка из URL ────────────────────────────────────────────────────

def fetch_url(url: str, timeout: int = 15) -> str:
    """Скачать подписку по URL с защитой от SSRF."""
    # Валидация схемы — только http/https
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        print(f'Ошибка: недопустимая схема {parsed.scheme!r}. '
              f'Разрешены только http:// и https://', file=sys.stderr)
        sys.exit(1)

    # Валидация хоста — отклонить внутренние адреса
    host = parsed.hostname or ''
    if not host:
        print('Ошибка: URL не содержит хост', file=sys.stderr)
        sys.exit(1)
    if (host in ('localhost', '127.0.0.1', '::1')
            or host.startswith('169.254.')
            or host.startswith('192.168.')
            or host.startswith('10.')
            or host.endswith('.local')):
        print(f'Ошибка: недопустимый хост {host!r} (внутренний адрес)',
              file=sys.stderr)
        sys.exit(1)

    # SSL контекст с явной верификацией
    ssl_ctx = ssl.create_default_context()
    ca_paths = [
        '/etc/ssl/certs/ca-certificates.crt',
        '/etc/ssl/certs',
        '/usr/share/ca-certificates',
    ]
    if not any(os.path.exists(p) for p in ca_paths):
        print('ПРЕДУПРЕЖДЕНИЕ: CA-сертификаты не найдены. '
              'SSL верификация отключена. '
              'Установите: opkg install ca-bundle', file=sys.stderr)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    # Ограничить количество редиректов и проверять их схему
    class LimitedRedirectHandler(urllib.request.HTTPRedirectHandler):
        redirect_count = 0

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            new_parsed = urllib.parse.urlparse(newurl)
            if new_parsed.scheme not in ('http', 'https'):
                raise URLError(
                    f'Редирект на недопустимую схему: {new_parsed.scheme}')
            self.redirect_count += 1
            if self.redirect_count > 3:
                raise URLError('Превышен лимит редиректов (3)')
            return super().redirect_request(
                req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(
        LimitedRedirectHandler(),
        urllib.request.HTTPSHandler(context=ssl_ctx))

    headers = {'User-Agent': 'ClashforWindows/0.19.0'}
    req = urllib.request.Request(url, headers=headers)

    try:
        with opener.open(req, timeout=timeout) as resp:
            # Ограничить размер ответа — 5 МБ достаточно для любой подписки
            MAX_SIZE = 5 * 1024 * 1024
            data = resp.read(MAX_SIZE + 1)
            if len(data) > MAX_SIZE:
                print(f'Ошибка: ответ превышает лимит '
                      f'{MAX_SIZE // 1024 // 1024} МБ', file=sys.stderr)
                sys.exit(1)
            return data.decode('utf-8', errors='replace')
    except HTTPError as e:
        print(f'HTTP ошибка {e.code}: {url}', file=sys.stderr)
        sys.exit(1)
    except URLError as e:
        print(f'Ошибка подключения: {e.reason}', file=sys.stderr)
        sys.exit(1)


# ── CLI ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='4eburNet Subscription Converter')
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument('-i', '--input',  help='Файл подписки')
    src.add_argument('--url',          help='URL подписки')
    parser.add_argument('-o', '--output',
                        help='Выходной файл (по умолчанию: stdout)')
    parser.add_argument('--format',
                        choices=['auto', 'clash', 'base64',
                                 'urilist', 'singbox'],
                        default='auto',
                        help='Формат входных данных (default: auto)')
    parser.add_argument('--no-rules',  action='store_true',
                        help='Не импортировать правила (только серверы)')
    parser.add_argument('--no-groups', action='store_true',
                        help='Не импортировать proxy-groups')
    parser.add_argument('--max-rules', type=int, default=512,
                        help='Максимум правил (default: 512)')
    parser.add_argument('--max-servers', type=int, default=500,
                        help='Максимум серверов (default: 500)')
    parser.add_argument('--append',   action='store_true',
                        help='Добавить к существующему конфигу')
    args = parser.parse_args()

    # Загрузить данные
    if args.url:
        print(f'Загрузка: {args.url}', file=sys.stderr)
        data = fetch_url(args.url)
    else:
        with open(args.input, 'r', encoding='utf-8', errors='replace') as f:
            data = f.read()

    # Определить формат
    fmt = args.format if args.format != 'auto' else detect_format(data)
    print(f'Формат: {fmt}', file=sys.stderr)

    # Парсить
    servers = []
    groups  = []
    rules   = []

    max_srv = args.max_servers

    providers = []

    if fmt == 'clash':
        servers, providers, groups, rules = parse_clash_yaml(data, max_srv)
    elif fmt in ('base64', 'urilist'):
        servers = parse_base64_subscription(data, max_srv)
    elif fmt == 'singbox':
        servers, rules = parse_singbox_json(data, max_srv)

    # Применить ограничения
    if args.no_groups:
        groups = []
    if args.no_rules:
        rules = []
    if len(rules) > args.max_rules:
        print(f'  [truncate] правил: {len(rules)} → {args.max_rules}',
              file=sys.stderr)
        rules = rules[:args.max_rules]

    print(f'Серверов:    {len(servers)}',   file=sys.stderr)
    print(f'Провайдеров: {len(providers)}', file=sys.stderr)
    print(f'Групп:       {len(groups)}',    file=sys.stderr)
    print(f'Правил:      {len(rules)}',     file=sys.stderr)

    if not servers and not groups and not rules:
        print('Ничего не найдено для импорта', file=sys.stderr)
        sys.exit(1)

    uci_output = generate_uci(servers, groups, rules, args.append,
                              providers=providers)

    if args.output:
        mode = 'a' if args.append else 'w'
        with open(args.output, mode, encoding='utf-8') as f:
            f.write(uci_output)
        print(f'Записано в: {args.output}', file=sys.stderr)
    else:
        print(uci_output)


if __name__ == '__main__':
    main()
