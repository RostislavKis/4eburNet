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

ОГРАНИЧЕНИЯ:
  - YAML anchors (&name / *alias): поддерживаются только при наличии PyYAML.
    Без PyYAML используется построчный fallback — anchors НЕ разворачиваются.
    При наличии anchors без PyYAML: pip3 install pyyaml
  - Emoji в именах серверов (U+1F000+) удаляются _uci_safe() — UCI их не поддерживает.
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
            'protocol':  'shadowsocks',
            'name':      name or host,
            'address':   host,
            'port':      int(port),
            'password':  password,
            'ss_method': method,
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


def _extract_ip(server_str) -> str:
    """Извлечь IP из DNS server строки: 'https://dns/q', '8.8.8.8', '8.8.8.8#53'.

    WHY (G15-4): для nameserver-policy upstream вызывать НЕ нужно — там
    URL DoH должен сохраниться целиком. Эта функция используется только
    для nameserver/fallback (там ожидается голый IP).
    """
    import re
    m = re.search(r'(\d{1,3}\.){3}\d{1,3}', str(server_str))
    return m.group(0) if m else str(server_str).split('#')[0].split('/')[0]


def _classify_dns_upstream(server_str) -> dict:
    """Классифицировать DNS upstream строку для UCI dns_policy секции (G15-4).

    Возвращает dict с ключами {type, upstream, sni}:
      'https://dns.google/dns-query'  → {type: 'doh', upstream: <URL>,    sni: 'dns.google'}
      'tls://1.1.1.1:853'             → {type: 'dot', upstream: '1.1.1.1', sni: ''}
      '8.8.8.8' / '8.8.8.8#53'        → {type: 'udp', upstream: '8.8.8.8', sni: ''}
    """
    s = str(server_str).strip()
    low = s.lower()
    if low.startswith('https://') or low.startswith('http://'):
        # DoH: сохраняем полный URL, sni извлекаем из hostname
        try:
            host = urllib.parse.urlparse(s).hostname or ''
        except Exception:
            host = ''
        return {'type': 'doh', 'upstream': s, 'sni': host}
    if low.startswith('tls://') or low.startswith('dot://'):
        # DoT: убираем схему, оставляем хост (порт config.c подставит как 853)
        rest = s.split('://', 1)[1]
        host = rest.split(':', 1)[0].split('#', 1)[0]
        return {'type': 'dot', 'upstream': host, 'sni': host}
    # plain UDP: формат 'IP' или 'IP#port' — port для UDP игнорируется парсером
    plain = s.split('#', 1)[0]
    return {'type': 'udp', 'upstream': plain, 'sni': ''}


# Явный маппинг сирот из анализа config.yaml.
# WHY: провайдеры объявлены в rule-providers, но не упомянуты в RULE-SET
# правилах конфига. Автоматически генерируем RULE-SET правила чтобы
# все 34 списка скачивались и участвовали в маршрутизации.
# Маппинг определён анализом групп и правил Flint2-конфига:
# - Discord/мессенджеры → TELEGRAM (канал с минимальным RT)
# - Иностранный контент/сервисы → GEMINI (основная proxy группа)
_ORPHAN_GROUP_MAP = {
    'youtube':        '🤖 GEMINI',
    'youtube-ip':     '🤖 GEMINI',
    'discord-domain': '✈️ TELEGRAM',
    'discord-ip':     '✈️ TELEGRAM',
    'discord-txt':    '✈️ TELEGRAM',
    'messengers':     '✈️ TELEGRAM',
    'xiaomi':         '🤖 GEMINI',
    'jetbrains':      '🤖 GEMINI',
    'games':          '🤖 GEMINI',
    'education':      '🤖 GEMINI',
    'art':            '🤖 GEMINI',
    'casino':         '🤖 GEMINI',
    'music':          '🤖 GEMINI',
    'news':           '🤖 GEMINI',
    'porn':           '🤖 GEMINI',
    'shop':           '🤖 GEMINI',
    'social':         '🤖 GEMINI',
    'video':          '🤖 GEMINI',
    'anime-ip':       '🤖 GEMINI',
}


def _guess_group_for_provider(name, available_groups):
    """Определить целевую группу для orphan rule-provider по маппингу."""
    if name in _ORPHAN_GROUP_MAP:
        target = _ORPHAN_GROUP_MAP[name]
        if target in available_groups:
            return target
        # Группа переименована — fallback на любую GEMINI/PROXY группу
        for g in available_groups:
            if 'GEMINI' in g.upper() or 'PROXY' in g.upper():
                return g
    # Неизвестная сирота — fallback на первую GEMINI/PROXY группу
    for g in available_groups:
        if 'GEMINI' in g.upper() or 'PROXY' in g.upper():
            return g
    return available_groups[0] if available_groups else 'PROXY'


def _convert_clash_rule_providers(doc: dict) -> list:
    """Конвертирует rule-providers Clash YAML → UCI rule_provider секции.

    WHY: rule-providers задают внешние наборы правил (RULE-SET).
    Без конвертации все RULE-SET правила указывают на несуществующие
    провайдеры в 4eburnet → cache_load() возвращает NULL → matching MISS,
    весь трафик падает в MATCH catch-all (DIRECT) и обходит группы.
    UCI ключи строго совпадают с config.c SECTION_RULE_PROVIDER:
    name, type, url, path, format (Clash behavior), interval, enabled.
    """
    out = []
    rps = doc.get('rule-providers') or {}
    if not isinstance(rps, dict):
        return out

    behavior_map = {
        'domain':    'domain',
        'ipcidr':    'ipcidr',
        'classical': 'classical',
    }

    for name, p in rps.items():
        if not isinstance(p, dict):
            print(f"[WARNING] sub_convert: rule-provider '{name}': "
                  f"невалидная структура — пропущен", file=sys.stderr)
            continue
        ptype    = str(p.get('type', 'http')).strip().lower()
        url      = str(p.get('url', '')).strip()
        path     = str(p.get('path', '')).strip()
        behavior = str(p.get('behavior', 'domain')).strip().lower()
        # file_format: 'text'/'yaml'/'mrs' — формат файла (не тип правил).
        # WHY: behavior = тип содержимого (domain/ipcidr/classical);
        # format = кодировка файла (text/yaml/mrs). Загрузчик должен знать оба.
        file_fmt = str(p.get('format', '')).strip().lower()
        interval = p.get('interval', 86400)

        if ptype not in ('http', 'file'):
            print(f"[WARNING] sub_convert: rule-provider '{name}': "
                  f"тип '{ptype}' не поддержан (нужно http|file) — пропущен",
                  file=sys.stderr)
            continue
        if ptype == 'http' and not url:
            print(f"[WARNING] sub_convert: rule-provider '{name}': "
                  f"type=http без url — пропущен", file=sys.stderr)
            continue
        if ptype == 'file' and not path:
            print(f"[WARNING] sub_convert: rule-provider '{name}': "
                  f"type=file без path — пропущен", file=sys.stderr)
            continue
        fmt = behavior_map.get(behavior)
        if fmt is None:
            print(f"[WARNING] sub_convert: rule-provider '{name}': "
                  f"behavior '{behavior}' не поддержан "
                  f"(нужно domain|ipcidr|classical) — fallback classical",
                  file=sys.stderr)
            fmt = 'classical'

        out.append({
            'name':        name,
            'type':        ptype,
            'url':         url,
            'path':        path,
            'format':      fmt,
            'file_format': file_fmt,
            'interval':    str(int(interval)) if str(interval).strip().isdigit()
                           else str(interval),
            'enabled':     '1',
        })
    return out


def _warn_unsupported_sections(doc: dict) -> None:
    """Логировать секции Clash которые не имеют прямого UCI эквивалента
    в 4eburnet — sniffer / tun / mode (если значение != 'rule').

    WHY: эти секции раньше игнорировались молча, что создавало ложное
    впечатление полной конвертации. Пользователь не знал что их
    конфигурация (sniffer protocol detection, TUN interface, global mode)
    не применилась к 4eburnet и нужно настраивать вручную.
    """
    # sniffer: enable=true конвертируется автоматически в _parse_clash_yaml_native
    # (dpi_enabled + sniffer_tls/http → dns_opts). Здесь логируем только enable=false.
    sniffer = doc.get('sniffer')
    if isinstance(sniffer, dict) and not sniffer.get('enable'):
        print("[INFO] sub_convert: sniffer присутствует с enable=false — "
              "пропущено как ожидаемо.", file=sys.stderr)

    # tun: 4eburnet перехватывает трафик через nftables TPROXY, не TUN.
    tun = doc.get('tun')
    if isinstance(tun, dict):
        if tun.get('enable'):
            print("[WARNING] sub_convert: tun.enable=true — 4eburnet использует "
                  "nftables TPROXY вместо виртуального TUN. Секция tun "
                  "полностью игнорируется. Transparent proxy настраивается "
                  "автоматически через nftables tproxy chain.",
                  file=sys.stderr)
        else:
            print("[INFO] sub_convert: tun присутствует с enable=false — "
                  "пропущено как ожидаемо.", file=sys.stderr)

    # mode: rule/global/direct конвертируются; неизвестные режимы — WARNING.
    mode = doc.get('mode')
    if mode is not None:
        mode_norm = str(mode).strip().lower()
        if mode_norm and mode_norm not in ('rule', 'global', 'direct'):
            print(f"[WARNING] sub_convert: mode='{mode}' — нераспознанный режим, "
                  f"пропущен. Поддержаны: rule, global, direct.",
                  file=sys.stderr)


def _parse_clash_yaml_native(doc: dict, max_servers: int = 500) -> tuple:
    """Парсить Clash YAML через PyYAML dict (anchors развёрнуты).

    Возвращает (servers, proxy_providers, groups, rules, dns_opts,
                rule_providers).
    """
    servers, providers, groups, rules, dns_opts = [], [], [], [], []

    # proxies → servers
    for p in (doc.get('proxies') or [])[:max_servers]:
        _clash_proxy_to_server(p, servers)

    # proxy-providers → UCI proxy_provider секции
    for name, pd in (doc.get('proxy-providers') or {}).items():
        if not isinstance(pd, dict):
            continue
        hc = pd.get('health-check') or {}
        # Кастомные заголовки: header: {Name: [Value]} → ["Name: Value"]
        hdr_dict = pd.get('header') or {}
        headers = []
        for hname, hval in hdr_dict.items():
            v = hval[0] if isinstance(hval, list) and hval else str(hval)
            headers.append(f'{hname}: {v}')
        providers.append({
            'name':            name,
            'url':             pd.get('url', ''),
            'interval':        str(pd.get('interval', 3600)),
            'health_url':      hc.get('url', ''),
            'health_interval': str(hc.get('interval', 300)),
            'enabled':         '1',
            'headers':         headers,
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
            # EC-12/13: список, а не space-separated строка — безопасно при именах с пробелами
            grp['providers'] = [str(x) for x in g['use']]
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

    # fake-ip-filter → traffic_rule DIRECT (вставляется В НАЧАЛО rules).
    # WHY: домены здесь должны получать реальный IP, а не fake-IP.
    # Без этого ломается captive-detection (apple/microsoft), российские
    # сайты, локальные домены. priority ASC: первые правила в массиве
    # срабатывают раньше → MATCH catch-all останется последним.
    fif_rules = _parse_fake_ip_filter(doc.get('dns') or {})
    rules = fif_rules + rules

    # dns: секция → UCI dns опции
    dns = doc.get('dns') or {}
    if dns and isinstance(dns, dict):
        nameservers = dns.get('nameserver') or []
        if nameservers:
            cls = _classify_dns_upstream(nameservers[0])
            if cls['type'] == 'doh':
                dns_opts.append(('upstream_doh', cls['upstream']))
            elif cls['type'] == 'dot':
                dns_opts.append(('upstream_dot', cls['upstream']))
            else:
                dns_opts.append(('upstream_default', cls['upstream']))
        # EC-7: все nameserver-а (не только первый)
        for ns in nameservers[1:]:
            cls = _classify_dns_upstream(ns)
            dns_opts.append(('upstream_doh_alt', cls['upstream']))
        fallback = dns.get('fallback') or []
        if fallback:
            cls = _classify_dns_upstream(fallback[0])
            if cls['type'] == 'doh':
                dns_opts.append(('upstream_doh_fallback', cls['upstream']))
            elif cls['type'] == 'dot':
                dns_opts.append(('upstream_dot_fallback', cls['upstream']))
            else:
                dns_opts.append(('upstream_fallback', cls['upstream']))
        # EC-7: все остальные fallback
        for fb in fallback[1:]:
            cls = _classify_dns_upstream(fb)
            dns_opts.append(('upstream_dot_fallback_alt', cls['upstream']))
        # EC-8: default-nameserver (bootstrap для DoH до инициализации wolfSSL)
        default_ns = dns.get('default-nameserver') or []
        if default_ns:
            ns_list = default_ns if isinstance(default_ns, list) else [default_ns]
            for i, ns in enumerate(ns_list):
                dns_opts.append(('bootstrap_dns' if i == 0 else 'bootstrap_dns_alt',
                                 str(ns)))
        # EC-9: direct-nameserver (для РФ-доменов без прокси)
        direct_ns = dns.get('direct-nameserver') or []
        if direct_ns:
            ns_list = direct_ns if isinstance(direct_ns, list) else [direct_ns]
            for ns in ns_list:
                dns_opts.append(('direct_nameserver', str(ns)))
        # EC-10: fake-ip-filter-mode (blacklist/whitelist)
        fif_mode = dns.get('fake-ip-filter-mode', '')
        if fif_mode:
            dns_opts.append(('fake_ip_filter_mode', str(fif_mode)))
        # EC-11: proxy-server-nameserver
        proxy_ns = dns.get('proxy-server-nameserver') or []
        if proxy_ns:
            ns_list = proxy_ns if isinstance(proxy_ns, list) else [proxy_ns]
            for ns in ns_list:
                dns_opts.append(('proxy_server_nameserver', str(ns)))
        fip = dns.get('fake-ip-range', '')
        if fip:
            dns_opts.append(('fake_ip_range', str(fip)))
        # fake-ip mode
        # WHY: парсер ожидает fake_ip_enabled в секции dns (config.c SECTION_DNS),
        # main_fake_ip_enabled → "Неизвестная опция 4eburnet" → fake-IP не включается.
        if str(dns.get('enhanced-mode', '')).strip().lower() == 'fake-ip':
            dns_opts.append(('dns_fake_ip_enabled', '1'))
        # fake-ip-filter → main section (дополнительно к traffic_rules выше).
        # WHY: traffic_rules маршрутизируют трафик; main_fake_ip_filter говорит
        # DNS-демону не выдавать fake-IP для этих доменов.
        fif = dns.get('fake-ip-filter') or []
        for d in [str(x).strip() for x in fif[:50] if str(x).strip()]:
            dns_opts.append(('main_fake_ip_filter', d))
        # nameserver-policy → dns_policy секция (G15-4).
        # WHY: dns_rule в демоне (config.c SECTION_DNS_RULE) парсит только
        # type+pattern, поле upstream игнорируется. Маршрутизация домен→upstream
        # реально работает через SECTION_DNS_POLICY (pattern+upstream+type+sni).
        for domain, srv_list in (dns.get('nameserver-policy') or {}).items():
            raw = srv_list[0] if isinstance(srv_list, list) else srv_list
            cls = _classify_dns_upstream(raw)
            dns_opts.append(('dns_policy', {
                'pattern':  domain,
                'upstream': cls['upstream'],
                'type':     cls['type'],
                'sni':      cls['sni'],
            }))

    # mode → main секция
    mode_str = str(doc.get('mode', '')).strip().lower()
    _mode_map = {'rule': 'rules', 'global': 'global', 'direct': 'direct'}
    if mode_str in _mode_map:
        dns_opts.append(('main_mode', _mode_map[mode_str]))

    # mixed-port / socks-port / port → mixed_port
    for _mp_key in ('mixed-port', 'socks-port', 'port'):
        _mp_val = doc.get(_mp_key, 0)
        try:
            _mp_int = int(_mp_val)
        except (TypeError, ValueError):
            _mp_int = 0
        if _mp_int > 0:
            dns_opts.append(('main_mixed_port', str(_mp_int)))
            break

    # hosts → DNS статические записи
    hosts = doc.get('hosts') or {}
    if isinstance(hosts, dict) and hosts:
        items = list(hosts.items())
        for domain, ip in items[:20]:
            dns_opts.append(('dns_static_host', f'{domain}={ip}'))
        if len(items) > 20:
            print(f"[INFO] sub_convert: hosts: {len(items)} записей, "
                  f"добавлены первые 20", file=sys.stderr)

    # rule-providers → UCI rule_provider секции (KB-5)
    rule_providers = _convert_clash_rule_providers(doc)

    # Orphan-провайдеры: объявлены в rule-providers, но нет RULE-SET ссылок.
    # WHY: вместо фильтрации — генерируем RULE-SET правила автоматически.
    # Это активирует все провайдеры: списки скачиваются и участвуют в маршрутизации.
    # Авто-правила добавляются в конец (перед MATCH catch-all): явные правила конфига
    # имеют приоритет над авто-маппингом.
    if rule_providers:
        referenced = {r['value'] for r in rules if r.get('type') == 'rule_set'}
        orphan_set = {rp['name'] for rp in rule_providers
                      if rp['name'] not in referenced}
        if orphan_set:
            available_groups = [g['name'] for g in groups]
            for name in sorted(orphan_set):
                target = _guess_group_for_provider(name, available_groups)
                rules.append({'type': 'rule_set', 'value': name, 'target': target})
                print(f"[INFO] sub_convert: orphan '{name}' → {target} (авто-правило)",
                      file=sys.stderr)

    # sniffer → UCI main dpi_enabled + sniffer_tls/sniffer_http (автоматическая конвертация)
    sniffer_cfg = doc.get('sniffer') or {}
    if isinstance(sniffer_cfg, dict) and sniffer_cfg.get('enable', False):
        # WHY: sniffer.enable=true маппируется в 4eburNet DPI pipeline:
        # dpi_enabled=1 активирует диспетчер DPI, sniffer_tls — TLS SNI extractor,
        # sniffer_http — HTTP Host header extractor (только если явно включён).
        dns_opts.append(('main_dpi_enabled', '1'))
        dns_opts.append(('main_sniffer_tls', '1'))
        sniff_protos = sniffer_cfg.get('sniff', {})
        if isinstance(sniff_protos, dict) and 'HTTP' in sniff_protos:
            dns_opts.append(('main_sniffer_http', '1'))
        bypass = sniffer_cfg.get('skip-domain', []) or []
        for domain in (bypass[:64] if isinstance(bypass, list) else []):
            dns_opts.append(('main_sniffer_bypass', str(domain)))

    # Warnings для неконвертируемых секций (KB-5)
    _warn_unsupported_sections(doc)

    return servers, providers, groups, rules, dns_opts, rule_providers


def parse_clash_yaml(data: str, max_servers: int = 500) -> tuple:
    """Парсить Clash/Mihomo YAML.
    Возвращает (servers, proxy_providers, groups, rules, dns_opts,
                rule_providers).
    PyYAML если доступен (разворачивает anchors), иначе построчный fallback.
    Fallback не парсит rule-providers/dns/sniffer/tun (только PyYAML)."""

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

    if 'rule-providers:' in data or 'sniffer:' in data or 'tun:' in data:
        print("[WARNING] sub_convert: PyYAML недоступен — "
              "rule-providers/sniffer/tun секции не парсятся в fallback. "
              "Установите: pip3 install pyyaml", file=sys.stderr)

    # fallback не парсит rule-providers/dns/sniffer/tun
    return servers, [], groups, rules, [], []


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
        _ws_opts = proxy.get('ws-opts', {}) if isinstance(proxy.get('ws-opts'), dict) else {}
        # XUDP/Mux.Cool: mihomo default — если udp=true и не задано
        # packet-encoding явно, активируем xudp (vless.go:454).
        _pe = proxy.get('packet-encoding', '')
        if not _pe and proxy.get('udp', False):
            _pe = 'xudp'
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
            'reality_short_id': proxy.get('reality-opts', {}).get('short-id', '')
                               if isinstance(proxy.get('reality-opts'), dict)
                               else proxy.get('sid', ''),
            'sni':         proxy.get('servername', proxy.get('sni', '')),
            'ws_path':     _ws_opts.get('path', ''),
            'ws_host':     (_ws_opts.get('headers', {}) or {}).get('Host', ''),
            'packet_encoding': _pe,
        })
    elif ptype == 'trojan':
        _ro_trj = proxy.get('reality-opts', {})
        if not isinstance(_ro_trj, dict):
            _ro_trj = {}
        _grpc_opts_trj = proxy.get('grpc-opts', {})
        if not isinstance(_grpc_opts_trj, dict):
            _grpc_opts_trj = {}
        _ws_opts_trj = proxy.get('ws-opts', {})
        if not isinstance(_ws_opts_trj, dict):
            _ws_opts_trj = {}
        _net_trj = proxy.get('network', 'raw')
        srv = {
            'protocol':           'trojan',
            'name':               name,
            'address':            host,
            'port':               int(port),
            'password':           proxy.get('password', ''),
            'sni':                proxy.get('sni', ''),
            'transport':          _net_trj,
            'reality_pbk':        _ro_trj.get('public-key', ''),
            'reality_short_id':   _ro_trj.get('short-id', ''),
            'reality_fingerprint': proxy.get('client-fingerprint', ''),
            'reality_sni':        proxy.get('servername', proxy.get('sni', '')),
            'packet_encoding':    proxy.get('packet-encoding', ''),
        }
        if _net_trj == 'grpc':
            srv['grpc_service_name'] = _grpc_opts_trj.get('grpc-service-name', '')
        elif _net_trj in ('ws', 'websocket'):
            srv['ws_path'] = _ws_opts_trj.get('path', '')
            srv['ws_host'] = (_ws_opts_trj.get('headers', {}) or {}).get('Host', '')
        _apply_shadowtls(proxy, srv)
        servers.append(srv)
    elif ptype in ('ss', 'shadowsocks'):
        srv = {
            'protocol':  'shadowsocks',
            'name':      name,
            'address':   host,
            'port':      int(port),
            'password':  proxy.get('password', ''),
            'ss_method': proxy.get('cipher', '2022-blake3-chacha20-poly1305'),
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
    elif ptype == 'anytls':
        servers.append({
            'protocol':         'anytls',
            'name':             name,
            'address':          host,
            'port':             int(port),
            'anytls_password':  proxy.get('password', ''),
            'anytls_sni':       proxy.get('sni', host),
        })
    elif ptype == 'vmess':
        _ws_opts   = proxy.get('ws-opts',   {}) if isinstance(proxy.get('ws-opts'),   dict) else {}
        _grpc_opts = proxy.get('grpc-opts', {}) if isinstance(proxy.get('grpc-opts'), dict) else {}
        network = proxy.get('network', 'tcp')
        alter_id = int(proxy.get('alterId', proxy.get('alter-id', 0)) or 0)
        if alter_id > 0:
            print(f"  [vmess] alterId={alter_id} (legacy) не поддерживается, "
                  f"используется AEAD для '{name}'", file=sys.stderr)
        _net_map = {'ws': 'ws', 'websocket': 'ws', 'grpc': 'grpc',
                    'h2': 'h2', 'http': 'h2', 'httpupgrade': 'httpupgrade'}
        srv = {
            'protocol':       'vmess',
            'name':           name,
            'address':        host,
            'port':           int(port),
            'uuid':           proxy.get('uuid', ''),
            'vmess_security': proxy.get('cipher', proxy.get('security', 'auto')),
            'transport':      _net_map.get(network, 'raw'),
        }
        if network in ('ws', 'websocket'):
            srv['ws_path'] = _ws_opts.get('path', '/')
            srv['ws_host'] = (_ws_opts.get('headers') or {}).get('Host', '')
        elif network == 'grpc':
            srv['grpc_service_name'] = _grpc_opts.get('grpc-service-name', '')
        if proxy.get('tls'):
            srv['tls']              = '1'
            srv['sni']              = proxy.get('servername', proxy.get('sni', ''))
            srv['skip_cert_verify'] = '1' if proxy.get('skip-cert-verify') else '0'
        servers.append(srv)
    elif ptype in ('tuic', 'tuic5', 'tuic-v5'):
        relay_mode = proxy.get('udp-relay-mode', 'native')
        servers.append({
            'protocol':              'tuic',
            'name':                  name,
            'address':               host,
            'port':                  int(port),
            'tuic_uuid':             proxy.get('uuid', ''),
            'tuic_password':         proxy.get('password', ''),
            'tuic_udp_relay_mode':   'quic' if relay_mode == 'quic' else 'native',
        })
    elif ptype == 'wireguard':
        srv = {
            'protocol':    'awg',
            'name':        name,
            'address':     host,
            'port':        int(port),
            'awg_private_key': proxy.get('private-key', ''),
            'awg_public_key':  proxy.get('public-key', ''),
        }
        # WHY: ip: 172.16.0.2 в Clash YAML = virtual client IP для AWG ipstack.
        # Без awg_local_ip ipstack init возвращает EINVAL → handshake не запускается.
        local_ip = proxy.get('ip') or proxy.get('local-address')
        if local_ip:
            srv['awg_local_ip'] = str(local_ip).split('/')[0]  # snip /32 если есть
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
        # psk + keepalive (P-37)
        psk = proxy.get('pre-shared-key', '') or awg_opts.get('pre-shared-key', '')
        if psk:
            srv['awg_psk'] = str(psk)
        ka = (proxy.get('persistent-keepalive') or proxy.get('keepalive')
              or awg_opts.get('persistent-keepalive') or awg_opts.get('keepalive'))
        if ka:
            srv['awg_keepalive'] = str(int(ka))
        # P9-03: AWG mtu/dns/reserved
        mtu = proxy.get('mtu') or awg_opts.get('mtu')
        if mtu:
            srv['awg_mtu'] = str(int(mtu))
        dns = proxy.get('dns') or awg_opts.get('dns')
        if dns:
            srv['awg_dns'] = list(dns) if isinstance(dns, list) else [str(dns)]
        reserved = proxy.get('reserved') or awg_opts.get('reserved')
        if reserved:
            if isinstance(reserved, list):
                srv['awg_reserved'] = ','.join(str(b) for b in reserved)
            else:
                srv['awg_reserved'] = str(reserved)
        servers.append(srv)
    else:
        print(f'  [skip] неподдерживаемый тип: {ptype} ({name})',
              file=sys.stderr)


def _parse_fake_ip_filter(dns_section: dict) -> list:
    """Парсит fake-ip-filter из Clash dns секции и возвращает список traffic_rule.

    WHY: домены в fake-ip-filter (mihomo blacklist при mode=blacklist) НЕ должны
    получать fake-IP — они идут с реальным IP через DIRECT/WAN. Без этого
    ломается captive-detection iOS/Windows, российские сайты, dev-инфра.
    Правила выходят с target='DIRECT'; вызывающий код инсертит их в начало
    списка rules, чтобы priority ASC сработал РАНЬШЕ MATCH.
    """
    fif = dns_section.get('fake-ip-filter', []) or []
    out = []
    for raw in fif:
        if not isinstance(raw, str):
            continue
        pattern = raw.strip()
        if not pattern or pattern.startswith('#'):
            continue
        if pattern.startswith('+.'):
            rtype, value = 'domain_suffix', pattern[2:]
        elif pattern.startswith('*.'):
            rtype, value = 'domain_suffix', pattern[2:]
        elif '*' not in pattern and '+' not in pattern:
            rtype, value = 'domain', pattern
        else:
            # сложные паттерны (a*b, foo.+.bar) — пропускаем
            continue
        if not value:
            continue
        out.append({'type': rtype, 'value': value, 'target': 'DIRECT'})
    return out


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
        'IP-CIDR6':       'ip_cidr6',
        'GEOIP':          'geoip',
        'GEOSITE':        'geosite',
        'RULE-SET':       'rule_set',
        'MATCH':          'match',
        'DST-PORT':       'port',
        'SRC-PORT':       'src_port',
        'PROCESS-NAME':   'process_name',
        'OR':             None,
        'NOT':            None,
    }

    # EC-4: NOT-правила — явное предупреждение (демон не поддерживает)
    if rtype == 'NOT':
        rest = ','.join(parts[1:])
        print(f"[WARNING] sub_convert: NOT-правило пропущено (не поддерживается): {rest[:80]}",
              file=sys.stderr)
        return None

    # P9-03: OR-правила — произвольные sub-conditions, достаточно одного совпадения
    if rtype == 'OR':
        rest = ','.join(parts[1:])
        # Извлечь target — токен после последней закрывающей скобки
        m_target = re.search(r'\)\),([^,()]+)\s*$', rest)
        if not m_target:
            print(f"[WARNING] sub_convert: OR-правило без target: {rest}",
                  file=sys.stderr)
            return None
        target = m_target.group(1).strip()
        sub_conditions = []
        for sub_m in re.finditer(r'\(([^()]+)\)', rest):
            sub = sub_m.group(1)
            colon_idx = sub.find(',')
            if colon_idx < 0:
                continue
            cond_type  = sub[:colon_idx].strip().upper()
            cond_value = sub[colon_idx + 1:].strip()
            # Допустимые типы для sub-conditions OR
            _or_valid = {
                'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD',
                'IP-CIDR', 'IP-CIDR6', 'GEOIP', 'GEOSITE',
            }
            if cond_type in _or_valid:
                sub_conditions.append(f"{cond_type},{cond_value}")
        if not sub_conditions:
            print(f"[WARNING] sub_convert: OR-правило без условий: {rest}",
                  file=sys.stderr)
            return None
        return {'type': 'OR', 'or_conditions': sub_conditions, 'target': target}

    # P9-04: DOMAIN-REGEX → REGEX тип
    if rtype == 'DOMAIN-REGEX':
        if len(parts) < 3:
            return None
        value  = parts[1].strip()
        target = parts[2].strip()
        return {'type': 'REGEX', 'value': value, 'target': target}

    # P9-02: AND-правила — все sub-conditions в and_conditions (EC-3)
    if rtype == 'AND':
        rest = ','.join(parts[1:])
        m_target = re.search(r'\)\),([^,()]+)\s*$', rest)
        if not m_target:
            print(f"[WARNING] sub_convert: AND-правило не поддержано: {rest}",
                  file=sys.stderr)
            return None
        target = m_target.group(1).strip()
        and_conditions = []
        network_val = ''
        port_val    = ''
        for sub_m in re.finditer(r'\(([^()]+)\)', rest):
            sub = sub_m.group(1)
            colon_idx = sub.find(',')
            if colon_idx < 0:
                continue
            cond_type  = sub[:colon_idx].strip().upper()
            cond_value = sub[colon_idx + 1:].strip()
            and_conditions.append(f"{cond_type},{cond_value}")
            if cond_type == 'NETWORK':
                network_val = cond_value.lower()
            elif cond_type == 'DST-PORT':
                port_val = cond_value
        if and_conditions:
            return {'type': 'and', 'network': network_val, 'port': port_val,
                    'and_conditions': and_conditions, 'target': target}
        print(f"[WARNING] sub_convert: AND-правило без sub-conditions: {rest}",
              file=sys.stderr)
        return None

    if rtype not in type_map:
        print(f"[WARNING] sub_convert: неподдерживаемый тип правила '{rtype}' — пропущен", file=sys.stderr)
        return None
    uci_type = type_map[rtype]
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
            tls       = ob.get('tls') or {}
            reality   = tls.get('reality') or {}
            transport = ob.get('transport') or {}
            t_type    = transport.get('type', '')
            _sb_t_map = {'ws': 'ws', 'grpc': 'grpc', 'http': 'h2',
                         'httpupgrade': 'httpupgrade'}
            srv = {
                'protocol':       'vless',
                'name':           name,
                'address':        host,
                'port':           int(port),
                'uuid':           ob.get('uuid', ''),
                'transport':      _sb_t_map.get(t_type, 'raw'),
                'reality_pbk':    reality.get('public_key', ''),
                'reality_short_id': reality.get('short_id', ''),
                'sni':            tls.get('server_name', ''),
                'packet_encoding': ob.get('packet_encoding', ''),
            }
            if t_type == 'ws':
                srv['ws_path'] = transport.get('path', '/')
                srv['ws_host'] = (transport.get('headers') or {}).get('Host', '')
            elif t_type == 'grpc':
                srv['grpc_service_name'] = transport.get('service_name', '')
            servers.append(srv)
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
                'protocol':  'shadowsocks',
                'name':      name,
                'address':   host,
                'port':      int(port),
                'password':  ob.get('password', ''),
                'ss_method': ob.get('method', '2022-blake3-chacha20-poly1305'),
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
        elif ob_type == 'tuic':
            tls = ob.get('tls') or {}
            relay_mode = ob.get('udp_relay_mode', 'native')
            servers.append({
                'protocol':            'tuic',
                'name':                name,
                'address':             host,
                'port':                int(port),
                'tuic_uuid':           ob.get('uuid', ''),
                'tuic_password':       ob.get('password', ''),
                'tuic_udp_relay_mode': 'quic' if relay_mode == 'quic' else 'native',
                'sni':                 tls.get('server_name', ''),
            })
        elif ob_type == 'anytls':
            tls = ob.get('tls') or {}
            servers.append({
                'protocol':        'anytls',
                'name':            name,
                'address':         host,
                'port':            int(port),
                'anytls_password': ob.get('password', ''),
                'anytls_sni':      tls.get('server_name', host),
            })
        elif ob_type == 'wireguard':
            srv = {
                'protocol':        'awg',
                'name':            name,
                'address':         host,
                'port':            int(port),
                'awg_private_key': ob.get('private_key', ''),
                'awg_public_key':  ob.get('peer_public_key', ''),
                'awg_mtu':         str(ob.get('mtu', 1280)),
                'awg_jc':          '4',
                'awg_jmin':        '40',
                'awg_jmax':        '70',
            }
            psk = ob.get('pre_shared_key', '')
            if psk:
                srv['awg_psk'] = str(psk)
            local_addr = ob.get('local_address') or []
            if local_addr:
                srv['awg_local_ip'] = ','.join(str(a) for a in local_addr)
            servers.append(srv)

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

def _clean_regex_filter(s: str) -> str:
    """Очистить regex фильтр после _uci_safe(): удалить пустые альтернативы |.

    WHY: эмодзи-флаги стран (U+1F1xx) удаляются _uci_safe() → появляются
    последовательности вида |(||...|) которые матчат пустую строку и тем
    самым отсекают ВСЕ серверы из группы через отрицательный lookahead.
    """
    import re as _re
    # убрать все пустые альтернативы: (|a) → (a), (a|) → (a), (a||b) → (a|b)
    prev = None
    while prev != s:
        prev = s
        s = _re.sub(r'\|\|+', '|', s)   # схлопнуть цепочки ||
        s = _re.sub(r'\(([^()]*)\|(?=\))', r'(\1', s)   # (a|) → (a)
        s = _re.sub(r'\(\|([^()]*)\)', r'(\1', s)       # (|a) → (a)
    return s


def _uci_safe(s) -> str:
    """Привести строку к UCI-безопасному виду.

    UCI синтаксис: option key 'value'
    Фильтруем: control chars (<0x20), DEL (0x7F), одиночные кавычки,
    backslash, emoji (U+1F000+), private use, surrogates.
    """
    result = []
    for ch in str(s):
        cp = ord(ch)
        if cp < 0x20 or cp == 0x7F:
            continue  # control chars
        if ch in ("'", "\\"):
            continue  # UCI shell-unsafe
        if cp >= 0x1F000:
            continue  # emoji strip: UCI не поддерживает U+1F000+; имена серверов с emoji усекаются молча
        result.append(ch)
    return ''.join(result).strip()


def generate_uci(servers: list,
                 groups:  list,
                 rules:   list,
                 append:  bool = False,
                 providers: list = None,
                 dns_opts: list = None,
                 rule_providers: list = None) -> str:
    """Генерировать UCI конфиг для серверов, прокси-провайдеров, групп,
    правил, DNS и rule-провайдеров."""
    lines = []

    if not append:
        lines.extend([
            "#!/bin/sh",
            "# Сгенерировано sub_convert.py — применять через: sh /tmp/generated_uci.sh",
            "# Деплой ТОЛЬКО с Windows (не WSL): scp -O file root@router:/tmp/",
            "",
            "# КРИТИЧНО: main секция объявляется до импорта остального конфига",
            "uci set 4eburnet.main='4eburnet'",
            "uci set 4eburnet.main.enabled='1'",
            "",
            "uci import 4eburnet <<'UCIEOF'",
        ])

    for srv in servers:
        lines.append("config server")
        for key, val in srv.items():
            if isinstance(val, list):
                for item in val:
                    si = str(item).strip()
                    if si:
                        lines.append(f"\tlist {key}\t'{_uci_safe(si)}'")
            elif val and str(val).strip():
                lines.append(f"\toption {key}\t'{_uci_safe(val)}'")
        lines.append("")

    # rule-providers перед proxy-providers — порядок не критичен для UCI
    # парсинга в config.c (секции группируются по type), но даёт стабильный
    # diff при повторной конвертации одного и того же YAML.
    for rp in (rule_providers or []):
        lines.append("config rule_provider")
        for key in ('name', 'type', 'url', 'path', 'format', 'file_format',
                    'interval', 'enabled'):
            val = rp.get(key, '')
            if val == '' or val is None:
                continue
            lines.append(f"\toption {key}\t'{_uci_safe(str(val))}'")
        lines.append("")

    for prov in (providers or []):
        lines.append("config proxy_provider")
        for key in ('name', 'url', 'interval', 'health_url',
                     'health_interval', 'enabled'):
            val = prov.get(key, '')
            if val:
                lines.append(f"\toption {key}\t'{_uci_safe(str(val))}'")
        for i, hdr in enumerate((prov.get('headers') or [])[:8]):
            lines.append(f"\toption header_{i}\t'{_uci_safe(hdr)}'")
        lines.append("")

    for grp in groups:
        lines.append("config proxy_group")
        lines.append(f"\toption name\t'{_uci_safe(grp.get('name', ''))}'")
        gtype = grp.get('type', 'url-test').lower().replace('-', '_')
        lines.append(f"\toption type\t'{_uci_safe(gtype)}'")
        if grp.get('url'):
            lines.append(f"\toption url\t'{_uci_safe(grp['url'])}'")
        if grp.get('interval'):
            lines.append(f"\toption interval\t'{_uci_safe(grp['interval'])}'")
        if grp.get('proxies'):
            # WHY: всегда list servers — option servers дробится по пробелу в
            # config.c (strtok), а имена серверов содержат пробелы
            # («AWG 2.0 (2 Вариант)») → группа теряет серверы. list servers
            # сохраняет имя целиком. Строковый proxies трактуем как одно имя.
            proxies = grp['proxies'] if isinstance(grp['proxies'], list) \
                else [grp['proxies']]
            for s in proxies:
                lines.append(f"\tlist servers\t'{_uci_safe(str(s))}'")
        if grp.get('providers'):
            providers = grp['providers']
            if isinstance(providers, list):
                for p in providers:
                    lines.append(f"\tlist providers\t'{_uci_safe(p.replace(' ', '_'))}'")
            else:
                lines.append(f"\toption providers\t'{_uci_safe(str(providers))}'")
        if grp.get('filter'):
            lines.append(f"\toption filter\t'{_clean_regex_filter(_uci_safe(str(grp['filter'])))}'")
        lines.append(f"\toption enabled\t'1'")
        lines.append("")

    priority = 200
    for rule in rules:
        lines.append("config traffic_rule")
        lines.append(f"\toption type\t'{rule['type']}'")
        if rule.get('value'):
            lines.append(f"\toption value\t'{_uci_safe(rule['value'])}'")
        # AND-правила: network (tcp/udp) и port ("50000-65535" или "443")
        if rule.get('network'):
            lines.append(f"\toption network\t'{_uci_safe(rule['network'])}'")
        if rule.get('port'):
            lines.append(f"\toption port\t'{_uci_safe(rule['port'])}'")
        # SRC-PORT/PROCESS-NAME используют стандартный UCI option value (уже записан выше)
        # OR-правила: список вложенных условий (формат "TYPE,VALUE")
        for cond in rule.get('or_conditions', []):
            lines.append(f"\tlist or_condition\t'{_uci_safe(cond)}'")
        # AND-правила: все sub-conditions (EC-3)
        for cond in rule.get('and_conditions', []):
            lines.append(f"\tlist and_condition\t'{_uci_safe(cond)}'")
        lines.append(f"\toption target\t'{_uci_safe(rule['target'])}'")
        lines.append(f"\toption priority\t'{priority}'")
        lines.append("")
        priority += 1

    # DNS опции из Clash dns: секции
    # P9-01: записывать как UCI options в секцию dns, не как комментарии
    # G15-4: nameserver-policy → dns_policy (правильная семантика, не dns_rule)
    # WHY proxy_server_nameserver исключён: DNS-резолв доменов прокси-серверов ЧЕРЕЗ
    # сам прокси = циклический deadlock на EC330 (прокси ждёт DNS, DNS ждёт прокси —
    # ломал Telegram/api.telegram.org timeout). upstream_bypass=1.1.1.1 резолвит напрямую.
    _skip_keys = {'dns_rule', 'dns_policy', 'dns_static_host', 'proxy_server_nameserver'}
    # Ключи, которые должны записываться как UCI list (множественные значения)
    _list_dns_keys = {
        'upstream_doh_alt', 'upstream_dot_fallback_alt',
        'bootstrap_dns_alt', 'direct_nameserver', 'proxy_server_nameserver',
    }
    dns_uci      = [kv for kv in (dns_opts or [])
                    if kv[0] not in _skip_keys and not kv[0].startswith('main_')]
    dns_policies = [kv for kv in (dns_opts or []) if kv[0] == 'dns_policy']
    dns_hosts    = [kv[1] for kv in (dns_opts or []) if kv[0] == 'dns_static_host']
    main_opts    = [kv for kv in (dns_opts or []) if kv[0].startswith('main_')]
    if dns_uci or dns_hosts:
        lines.append("config dns 'dns'")
        lines.append("\toption enabled\t'1'")
        for key, val in dns_uci:
            if key in _list_dns_keys:
                lines.append(f"\tlist {key}\t'{_uci_safe(val)}'")
            else:
                lines.append(f"\toption {key}\t'{_uci_safe(val)}'")
        for host in dns_hosts:
            lines.append(f"\tlist static_hosts\t'{_uci_safe(host)}'")
        lines.append("")
    for _, p in dns_policies:
        lines.append("config dns_policy")
        for k in ('pattern', 'upstream', 'type', 'sni'):
            v = p.get(k, '')
            if v:
                lines.append(f"\toption {k}\t'{_uci_safe(v)}'")
        lines.append("")
    if main_opts:
        lines.append("config 4eburnet 'main'")
        lines.append("\toption enabled\t'1'")
        for key, val in main_opts:
            opt_name = key[5:]  # убрать prefix 'main_'
            if key in ('main_fake_ip_filter', 'main_sniffer_bypass'):
                lines.append(f"\tlist {opt_name}\t'{_uci_safe(val)}'")
            else:
                lines.append(f"\toption {opt_name}\t'{_uci_safe(val)}'")
        lines.append("")

    if not append:
        lines.extend([
            "UCIEOF",
            "",
            "# Восстановить upstream_bypass если был задан",
            "# uci set 4eburnet.dns.upstream_bypass='8.8.8.8'  # раскомментировать если нужно",
            "",
            "uci commit 4eburnet",
            "echo 'UCI применён. Перезапусти демон: /etc/init.d/4eburnet restart'",
        ])

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
    rule_providers = []

    dns_opts = []
    if fmt == 'clash':
        (servers, providers, groups, rules,
         dns_opts, rule_providers) = parse_clash_yaml(data, max_srv)
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

    print(f'Серверов:    {len(servers)}',         file=sys.stderr)
    print(f'Провайдеров: {len(providers)}',       file=sys.stderr)
    print(f'Rule-prov:   {len(rule_providers)}',  file=sys.stderr)
    print(f'Групп:       {len(groups)}',           file=sys.stderr)
    print(f'Правил:      {len(rules)}',            file=sys.stderr)

    if (not servers and not groups and not rules
            and not rule_providers):
        print('Ничего не найдено для импорта', file=sys.stderr)
        sys.exit(1)

    uci_output = generate_uci(servers, groups, rules, args.append,
                              providers=providers, dns_opts=dns_opts,
                              rule_providers=rule_providers)

    if args.output:
        mode = 'a' if args.append else 'w'
        with open(args.output, mode, encoding='utf-8') as f:
            f.write(uci_output)
        print(f'Записано в: {args.output}', file=sys.stderr)
    else:
        print(uci_output)


if __name__ == '__main__':
    main()
