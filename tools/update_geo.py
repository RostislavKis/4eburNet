#!/usr/bin/env python3
"""
4eburNet GeoIP/GeoSite/Rule-Set Updater

Скачивает geo-данные и конвертирует rule-set YAML в .lst файлы.
Результат сохраняется в filter репо (по умолчанию ../filter).

Использование:
  python tools/update_geo.py --filter-repo ../filter
  python tools/update_geo.py --dry-run
"""

import sys
import os
import re
import argparse
import math
import struct
import socket
import urllib.request
from urllib.error import URLError
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ── GeoIP RU ─────────────────────────────────────────────────────────

def ip_count_to_cidr(start_ip: str, count: int) -> str:
    """Преобразовать start_ip + count адресов в CIDR."""
    prefix_len = 32 - int(math.log2(count))
    return f'{start_ip}/{prefix_len}'


def fetch_geoip_ru(out_path: str) -> int:
    """Скачать RU IPv4 CIDR из RIPE NCC delegated."""
    url = 'https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-latest'
    print(f'  Скачиваю geoip-ru из {url}...', end=' ', flush=True)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': '4eburNet/1.0'})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read().decode('utf-8', errors='replace')
    except (URLError, OSError) as e:
        print(f'ОШИБКА: {e}')
        return -1

    cidrs = []
    for line in data.splitlines():
        parts = line.split('|')
        if len(parts) >= 5 and parts[1] == 'RU' and parts[2] == 'ipv4':
            try:
                start_ip = parts[3]
                count = int(parts[4])
                if count > 0 and (count & (count - 1)) == 0:
                    cidrs.append(ip_count_to_cidr(start_ip, count))
            except (ValueError, IndexError):
                continue

    with open(out_path, 'w') as f:
        f.write('\n'.join(sorted(cidrs)) + '\n')

    print(f'{len(cidrs)} CIDR')
    return len(cidrs)


# ── GeoSite RU ────────────────────────────────────────────────────────

RU_BASE_DOMAINS = [
    '*.ru', '*.xn--p1ai', '*.su',
    'vk.com', 'yandex.ru', 'mail.ru', 'ok.ru',
    'gosuslugi.ru', 'mos.ru', 'sberbank.ru', 'tinkoff.ru',
    'avito.ru', 'wildberries.ru', 'ozon.ru',
]


def fetch_geosite_ru(out_path: str) -> int:
    """Скачать RU домены из zapret-info + базовые."""
    url = 'https://raw.githubusercontent.com/zapret-info/z-i/master/nxdomain.txt'
    print(f'  Скачиваю geosite-ru из zapret-info...', end=' ', flush=True)

    domains = set(RU_BASE_DOMAINS)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': '4eburNet/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode('utf-8', errors='replace')

        for line in text.splitlines():
            domain = line.strip().lower()
            if domain and '.' in domain and not domain.startswith('#'):
                domain = re.sub(r'^www\.', '', domain)
                if len(domain) < 256:
                    domains.add(domain)
    except (URLError, OSError) as e:
        print(f'ОШИБКА: {e}')
        return -1

    with open(out_path, 'w') as f:
        f.write('\n'.join(sorted(domains)) + '\n')

    print(f'{len(domains)} доменов')
    return len(domains)


# ── GeoSite Ads ───────────────────────────────────────────────────────

def fetch_geosite_ads(out_path: str) -> int:
    """Скачать список рекламных доменов из oisd.nl."""
    url = 'https://big.oisd.nl/domainswild2'
    print(f'  Скачиваю geosite-ads из oisd.nl...', end=' ', flush=True)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': '4eburNet/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode('utf-8', errors='replace')
    except (URLError, OSError) as e:
        print(f'ОШИБКА: {e}')
        return -1

    domains = []
    for line in data.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            domains.append(line)

    with open(out_path, 'w') as f:
        f.write('\n'.join(domains) + '\n')

    print(f'{len(domains)} доменов')
    return len(domains)


# ── GeoSite Trackers (EasyPrivacy) ─────────────────────────────────────

_TRACKER_RE = re.compile(
    r'^\|\|([a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-zA-Z]{2,})\^')
_THREAT_RE = re.compile(
    r'^(?:0\.0\.0\.0|127\.0\.0\.1)[\s\t]+([a-zA-Z0-9][a-zA-Z0-9._-]+\.[a-zA-Z]{2,})')


def fetch_geosite_trackers(out_path: str) -> int:
    """Скачать список трекеров/аналитики из EasyPrivacy (easylist.to).
    Формат: ||domain.com^ → domain.com (ABP синтаксис)."""
    url = 'https://easylist.to/easylist/easyprivacy.txt'
    print(f'  Скачиваю geosite-trackers из EasyPrivacy...', end=' ', flush=True)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': '4eburNet/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode('utf-8', errors='replace')
    except (URLError, OSError) as e:
        print(f'ОШИБКА: {e}')
        return -1

    domains = set()
    for line in data.splitlines():
        m = _TRACKER_RE.match(line.strip())
        if m:
            domains.add(m.group(1).lower())

    if len(domains) < 1000:
        print(f'WARN: только {len(domains)} доменов — пропускаю запись')
        return 0
    domains = sorted(domains)
    tmp = out_path + '.tmp'
    try:
        with open(tmp, 'w') as f:
            f.write('\n'.join(domains) + '\n')
        os.replace(tmp, out_path)
    except Exception as e:
        try: os.unlink(tmp)
        except OSError: pass
        print(f'ОШИБКА записи: {e}')
        return -1

    print(f'{len(domains)} доменов')
    return len(domains)


# ── GeoSite Threats (URLhaus hostnames) ────────────────────────────────

def fetch_geosite_threats(out_path: str) -> int:
    """Скачать список malware/phishing хостов из URLhaus hostfile.
    Формат: 0.0.0.0 domain.com"""
    url = 'https://urlhaus.abuse.ch/downloads/hostfile/'
    print(f'  Скачиваю geosite-threats из URLhaus...', end=' ', flush=True)

    try:
        req = urllib.request.Request(url, headers={'User-Agent': '4eburNet/1.0'})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = resp.read().decode('utf-8', errors='replace')
    except (URLError, OSError) as e:
        print(f'ОШИБКА: {e}')
        return -1

    domains = set()
    for line in data.splitlines():
        m = _THREAT_RE.match(line.strip())
        if m:
            h = m.group(1).lower()
            if h != 'localhost':
                domains.add(h)

    if len(domains) < 100:
        print(f'WARN: только {len(domains)} доменов — пропускаю запись')
        return 0
    domains = sorted(domains)
    tmp = out_path + '.tmp'
    try:
        with open(tmp, 'w') as f:
            f.write('\n'.join(domains) + '\n')
        os.replace(tmp, out_path)
    except Exception as e:
        try: os.unlink(tmp)
        except OSError: pass
        print(f'ОШИБКА записи: {e}')
        return -1

    print(f'{len(domains)} доменов')
    return len(domains)


# ── Rule-sets из YAML ─────────────────────────────────────────────────

def convert_yaml_rulesets(filter_dir: str) -> int:
    """Конвертировать *.yaml из filter_dir в rule-sets/*.lst."""
    try:
        import yaml
    except ImportError:
        print('  [skip] PyYAML не установлен — rule-sets пропущены')
        return 0

    rulesets_dir = os.path.join(filter_dir, 'rule-sets')
    os.makedirs(rulesets_dir, exist_ok=True)

    yaml_files = [f for f in os.listdir(filter_dir)
                  if f.endswith('.yaml') and os.path.isfile(os.path.join(filter_dir, f))]

    total = 0
    for yf in sorted(yaml_files):
        ypath = os.path.join(filter_dir, yf)
        name = os.path.splitext(yf)[0]

        try:
            with open(ypath) as f:
                doc = yaml.safe_load(f)
        except Exception as e:
            print(f'  [warn] {yf}: {e}')
            continue

        entries = doc.get('payload') or doc if isinstance(doc, list) else []
        if isinstance(doc, dict):
            entries = doc.get('payload', [])

        values = []
        for entry in entries:
            s = str(entry).strip()
            if s.startswith('+'):
                s = s[1:].strip()
            # Извлечь value из "TYPE,value" или просто "domain"
            if ',' in s:
                parts = s.split(',', 2)
                rtype = parts[0].strip().upper()
                val = parts[1].strip() if len(parts) > 1 else ''
                if rtype in ('DOMAIN-SUFFIX', 'DOMAIN', 'DOMAIN-KEYWORD',
                             'IP-CIDR', 'IP-CIDR6'):
                    values.append(val)
            elif '.' in s or ':' in s:
                values.append(s)

        if values:
            out = os.path.join(rulesets_dir, f'{name}.lst')
            with open(out, 'w') as f:
                f.write('\n'.join(values) + '\n')
            print(f'  [OK] rule-sets/{name}.lst: {len(values)} записей')
            total += len(values)

    return total


# ── Git ───────────────────────────────────────────────────────────────

def git_commit_push(filter_dir: str, dry_run: bool) -> None:
    """Git commit + push изменений."""
    import subprocess

    def run(cmd):
        return subprocess.run(cmd, cwd=filter_dir, capture_output=True, text=True)

    run(['git', 'add', 'geo/', 'rule-sets/'])
    result = run(['git', 'status', '--porcelain'])

    if not result.stdout.strip():
        print('\n  Нет изменений для коммита.')
        return

    date = datetime.now().strftime('%Y-%m-%d')
    msg = f'geo: update {date}'

    if dry_run:
        print(f'\n  [DRY-RUN] git commit -m "{msg}" пропущен')
        return

    run(['git', 'commit', '-m', msg])
    print(f'\n  git commit -m "{msg}"')

    # Определить текущую ветку
    branch = run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'])
    br = branch.stdout.strip() or 'master'
    push = run(['git', 'push', 'origin', br])
    if push.returncode == 0:
        print('  git push OK')
    else:
        print(f'  git push ОШИБКА: {push.stderr.strip()}')


# ── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='4eburNet GeoIP Updater')
    parser.add_argument('--filter-repo', default=None,
                        help='Путь к filter репо (default: ../filter)')
    parser.add_argument('--dry-run', action='store_true',
                        help='Не коммитить и не пушить')
    args = parser.parse_args()

    filter_dir = args.filter_repo or os.path.join(SCRIPT_DIR, '..', '..', 'filter')
    filter_dir = os.path.abspath(filter_dir)

    print(f'Filter repo: {filter_dir}')

    # Создать директории
    geo_dir = os.path.join(filter_dir, 'geo')
    os.makedirs(geo_dir, exist_ok=True)

    # Инициализировать git если нет
    if not os.path.isdir(os.path.join(filter_dir, '.git')):
        import subprocess
        subprocess.run(['git', 'init'], cwd=filter_dir)
        print(f'  git init в {filter_dir}')

    print()

    # GeoIP RU
    n = fetch_geoip_ru(os.path.join(geo_dir, 'geoip-ru.lst'))
    if n < 0:
        print('  [FAIL] geoip-ru.lst')

    # GeoSite RU
    n = fetch_geosite_ru(os.path.join(geo_dir, 'geosite-ru.lst'))
    if n < 0:
        print('  [FAIL] geosite-ru.lst')

    # GeoSite Ads
    n = fetch_geosite_ads(os.path.join(geo_dir, 'geosite-ads.lst'))
    if n < 0:
        print('  [FAIL] geosite-ads.lst')

    # GeoSite Trackers
    n = fetch_geosite_trackers(os.path.join(geo_dir, 'geosite-trackers.lst'))
    if n < 0:
        print('  [FAIL] geosite-trackers.lst')

    # GeoSite Threats
    n = fetch_geosite_threats(os.path.join(geo_dir, 'geosite-threats.lst'))
    if n < 0:
        print('  [FAIL] geosite-threats.lst')

    print()

    # Rule-sets из YAML
    convert_yaml_rulesets(filter_dir)

    # Git commit
    git_commit_push(filter_dir, args.dry_run)

    print('\nГотово.')


if __name__ == '__main__':
    main()
