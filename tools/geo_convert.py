#!/usr/bin/env python3
"""
tools/geo_convert.py — конвертер гео-списков для phoenix-router.

Скачивает и нормализует .txt/.list/.yaml списки в .lst формат.
Запускается при сборке SDK или вручную.

Использование:
  python3 tools/geo_convert.py [--output DIR] [--source NAME] [--url URL]
                                [--format FORMAT] [--type TYPE]

Примеры:
  # Скачать все встроенные источники
  python3 tools/geo_convert.py --output /etc/phoenix/geo/

  # Скачать конкретный источник
  python3 tools/geo_convert.py --source geoip-ru --output ./geo/

  # Конвертировать локальный файл
  python3 tools/geo_convert.py --file russia.list \
      --format list --type ipcidr --output ./geo/ --name geoip-ru
"""

import argparse
import os
import sys
import re
import urllib.request
import urllib.error


# ── Встроенные источники ──────────────────────────────────────────────────

SOURCES = {
    "geoip-ru": {
        "url": "https://raw.githubusercontent.com/nicholasstephan/russia-ip-list/main/russia.list",
        "format": "list",
        "type": "ipcidr",
        "comment": "IP диапазоны РФ",
    },
    "geosite-ru": {
        "url": "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/ru",
        "format": "v2fly_data",
        "type": "domain",
        "comment": "Домены зоны .ru",
    },
    "geosite-ads": {
        "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "format": "hosts",
        "type": "domain",
        "comment": "Рекламные домены (универсальный)",
    },
    "antizapret": {
        "url": "https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv",
        "format": "csv_ru",
        "type": "mixed",
        "comment": "РКН блокировки (IP + домены)",
    },
}


# ── Валидация записей ─────────────────────────────────────────────────────

IPV4_CIDR_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
)
IPV6_CIDR_RE = re.compile(
    r'^[0-9a-fA-F:]+(/\d{1,3})?$'
)
DOMAIN_RE = re.compile(
    r'^\.?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)


def is_ipv4_cidr(s):
    return bool(IPV4_CIDR_RE.match(s)) and ':' not in s


def is_ipv6_cidr(s):
    # Проверяем что содержит двоеточие (IPv6 признак)
    return ':' in s and bool(IPV6_CIDR_RE.match(s.split('/')[0]))


def is_domain(s):
    return bool(DOMAIN_RE.match(s.lstrip('.'))) and '/' not in s


def normalize_entry(entry, entry_type):
    """
    Нормализовать запись в формат geo_loader.c:
      - CIDR: вернуть как есть (с /prefix)
      - Домен без точки: точное совпадение
      - Домен с точкой: суффикс совпадение (.example.com)
    Вернуть None если запись невалидна или не подходит для entry_type.
    """
    entry = entry.strip()
    if not entry or entry.startswith('#'):
        return None

    if entry_type in ('ipcidr', 'mixed'):
        if is_ipv4_cidr(entry):
            # Добавить /32 если нет префикса
            return entry if '/' in entry else entry + '/32'
        if is_ipv6_cidr(entry):
            return entry if '/' in entry else entry + '/128'
        if entry_type == 'mixed' and is_domain(entry):
            return entry.lower()

    if entry_type in ('domain', 'mixed'):
        if is_domain(entry):
            return entry.lower()

    return None


# ── Парсеры форматов ──────────────────────────────────────────────────────

def parse_txt(content, entry_type):
    """Простой текстовый список, одна запись на строку."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#') or line.startswith(';'):
            continue
        # Убрать инлайн комментарии
        if ' #' in line:
            line = line[:line.index(' #')].strip()
        entry = normalize_entry(line, entry_type)
        if entry:
            results.append(entry)
    return results


def parse_list(content, entry_type):
    """Clash/Mihomo .list формат — может содержать DOMAIN-SUFFIX,xxx."""
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Clash формат: DOMAIN-SUFFIX,google.com или просто google.com
        if ',' in line:
            parts = line.split(',', 2)
            rule_type = parts[0].upper()
            value = parts[1].strip() if len(parts) > 1 else ''
            if rule_type in ('DOMAIN-SUFFIX', 'DOMAIN_SUFFIX'):
                value = '.' + value.lstrip('.')
            elif rule_type in ('DOMAIN', 'DOMAIN-FULL'):
                pass  # точное совпадение
            elif rule_type in ('IP-CIDR', 'IP_CIDR', 'IP-CIDR6', 'IP_CIDR6'):
                # Убрать no-resolve суффикс
                value = value.split(',')[0]
            else:
                # Неизвестный тип — пропустить
                continue
            entry = normalize_entry(value, entry_type)
        else:
            entry = normalize_entry(line, entry_type)
        if entry:
            results.append(entry)
    return results


def parse_yaml(content, entry_type):
    """YAML с payload: списком."""
    results = []
    in_payload = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith('payload:'):
            in_payload = True
            continue
        if not in_payload:
            continue
        if stripped.startswith('#') or not stripped:
            continue
        # Конец payload если нет отступа и не список
        if not stripped.startswith('-') and not line.startswith(' ') \
                and not line.startswith('\t'):
            break
        # Убрать "- " в начале
        if stripped.startswith('- '):
            stripped = stripped[2:].strip()
        # Убрать кавычки
        stripped = stripped.strip('"\'')
        # Обработать как .list
        entry = parse_list(stripped, entry_type)
        results.extend(entry)
    return results


def parse_v2fly_data(content, entry_type):
    """
    v2fly domain-list-community data формат:
      domain:example.com
      full:www.example.com
      keyword:example
      include:other-list
      regexp:pattern  (пропускаем — нет поддержки в geo_loader)
    """
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        # Убрать @attributes
        if '@' in line:
            line = line[:line.index('@')].strip()
        if line.startswith('domain:'):
            val = '.' + line[7:].lstrip('.')
            if is_domain(val.lstrip('.')):
                results.append(val.lower())
        elif line.startswith('full:'):
            val = line[5:]
            if is_domain(val):
                results.append(val.lower())
        elif line.startswith('include:') or line.startswith('regexp:') \
                or line.startswith('keyword:'):
            pass  # пропустить
        else:
            # Без префикса — считаем суффиксом
            val = '.' + line.lstrip('.')
            if is_domain(line):
                results.append(val.lower())
    return results


def parse_hosts(content, entry_type):
    """
    /etc/hosts формат (StevenBlack и аналоги):
      0.0.0.0 example.com
      127.0.0.1 example.com
    """
    results = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 2:
            ip = parts[0]
            domain = parts[1]
            # Только блокировочные записи
            if ip not in ('0.0.0.0', '127.0.0.1', '::1', '::'):
                continue
            if domain in ('localhost', 'localhost.localdomain',
                          'local', 'broadcasthost'):
                continue
            if is_domain(domain):
                results.append(domain.lower())
    return results


def parse_csv_ru(content, entry_type):
    """
    Роскомнадзор dump.csv формат:
      ip|domain|date|link|subdomain
    Первая колонка может содержать IP или IP/prefix.
    """
    results = []
    for line in content.splitlines():
        if not line or line.startswith('#'):
            continue
        parts = line.split('|')
        if len(parts) < 2:
            continue
        ip_field = parts[0].strip()
        domain_field = parts[1].strip() if len(parts) > 1 else ''
        # IP/CIDR
        for ip in ip_field.split(';'):
            ip = ip.strip()
            if ip and (is_ipv4_cidr(ip) or is_ipv6_cidr(ip)):
                entry = normalize_entry(ip, 'ipcidr')
                if entry:
                    results.append(entry)
        # Домен
        if domain_field and entry_type in ('domain', 'mixed'):
            for d in domain_field.split(';'):
                d = d.strip().lstrip('*').lstrip('.')
                if d and is_domain(d):
                    results.append('.' + d.lower())
    return results


PARSERS = {
    'txt':        parse_txt,
    'list':       parse_list,
    'yaml':       parse_yaml,
    'yml':        parse_yaml,
    'v2fly_data': parse_v2fly_data,
    'hosts':      parse_hosts,
    'csv_ru':     parse_csv_ru,
}


def detect_format(filename):
    """Определить формат по расширению файла."""
    ext = os.path.splitext(filename)[1].lower().lstrip('.')
    return ext if ext in PARSERS else 'txt'


# ── Загрузка и запись ─────────────────────────────────────────────────────

def fetch_url(url, timeout=30):
    """Скачать содержимое URL."""
    print(f"  Загрузка: {url}", flush=True)
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'phoenix-router-geo-convert/1.0'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            # Попробовать декодировать UTF-8, потом cp1251 (РКН dump)
            try:
                return raw.decode('utf-8')
            except UnicodeDecodeError:
                return raw.decode('cp1251', errors='replace')
    except urllib.error.URLError as e:
        print(f"  ОШИБКА загрузки: {e}", file=sys.stderr)
        return None


def write_lst(entries, output_path, comment=''):
    """Записать нормализованные записи в .lst файл."""
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    # Дедупликация с сохранением порядка
    seen = set()
    unique = []
    for e in entries:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    with open(output_path, 'w', encoding='utf-8') as f:
        if comment:
            f.write(f'# {comment}\n')
        f.write(f'# Записей: {len(unique)}\n')
        f.write(f'# Сгенерировано: tools/geo_convert.py\n\n')
        for entry in unique:
            f.write(entry + '\n')
    print(f"  Записано: {output_path} ({len(unique)} записей)")
    return len(unique)


def convert_source(name, source, output_dir):
    """Скачать и конвертировать один источник."""
    print(f"\n[{name}] {source.get('comment', '')}")
    content = fetch_url(source['url'])
    if not content:
        return False
    fmt = source.get('format', 'txt')
    parser = PARSERS.get(fmt)
    if not parser:
        print(f"  ОШИБКА: неизвестный формат '{fmt}'", file=sys.stderr)
        return False
    entry_type = source.get('type', 'mixed')
    entries = parser(content, entry_type)
    if not entries:
        print(f"  ПРЕДУПРЕЖДЕНИЕ: список пустой после парсинга")
        return False
    output_path = os.path.join(output_dir, f'{name}.lst')
    write_lst(entries, output_path, source.get('comment', name))
    return True


def convert_file(filepath, fmt, entry_type, output_dir, name):
    """Конвертировать локальный файл."""
    print(f"\n[{name}] локальный файл: {filepath}")
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except OSError as e:
        print(f"  ОШИБКА: {e}", file=sys.stderr)
        return False
    parser = PARSERS.get(fmt or detect_format(filepath))
    if not parser:
        print(f"  ОШИБКА: неизвестный формат", file=sys.stderr)
        return False
    entries = parser(content, entry_type or 'mixed')
    if not entries:
        print("  ПРЕДУПРЕЖДЕНИЕ: список пустой после парсинга")
        return False
    output_path = os.path.join(output_dir, f'{name}.lst')
    write_lst(entries, output_path, name)
    return True


# ── CLI ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='phoenix-router geo list converter'
    )
    parser.add_argument('--output', '-o', default='./geo',
                        help='Директория для .lst файлов (default: ./geo)')
    parser.add_argument('--source', '-s',
                        help='Имя встроенного источника (geoip-ru, antizapret, ...)')
    parser.add_argument('--all', action='store_true',
                        help='Скачать все встроенные источники')
    parser.add_argument('--list-sources', action='store_true',
                        help='Показать список встроенных источников')
    parser.add_argument('--file', '-f',
                        help='Конвертировать локальный файл')
    parser.add_argument('--url', '-u',
                        help='Скачать и конвертировать URL')
    parser.add_argument('--format',
                        choices=list(PARSERS.keys()),
                        help='Формат входного файла')
    parser.add_argument('--type',
                        choices=['ipcidr', 'domain', 'mixed'],
                        default='mixed',
                        help='Тип записей (default: mixed)')
    parser.add_argument('--name', '-n', default='custom',
                        help='Имя выходного файла (без .lst)')
    args = parser.parse_args()

    if args.list_sources:
        print("Встроенные источники:")
        for name, src in SOURCES.items():
            print(f"  {name:20s} — {src.get('comment', '')}")
            print(f"  {'':20s}   формат: {src['format']}, тип: {src['type']}")
        return

    if args.file:
        ok = convert_file(args.file, args.format,
                          args.type, args.output, args.name)
        sys.exit(0 if ok else 1)

    if args.url:
        source = {
            'url': args.url,
            'format': args.format or 'txt',
            'type': args.type,
            'comment': args.name,
        }
        ok = convert_source(args.name, source, args.output)
        sys.exit(0 if ok else 1)

    if args.source:
        if args.source not in SOURCES:
            print(f"Неизвестный источник: {args.source}", file=sys.stderr)
            print(f"Доступные: {', '.join(SOURCES.keys())}")
            sys.exit(1)
        ok = convert_source(args.source, SOURCES[args.source], args.output)
        sys.exit(0 if ok else 1)

    if args.all:
        ok_count = 0
        for name, source in SOURCES.items():
            if convert_source(name, source, args.output):
                ok_count += 1
        print(f"\nГотово: {ok_count}/{len(SOURCES)} источников")
        sys.exit(0 if ok_count > 0 else 1)

    parser.print_help()


if __name__ == '__main__':
    main()
