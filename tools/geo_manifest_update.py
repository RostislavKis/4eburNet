#!/usr/bin/env python3
"""Обновляет updated_utc во всех манифестах geo профилей filter репо."""
import sys, json, datetime, os

filter_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(__file__), '..', '..', 'filter')
geo_dir = os.path.join(os.path.abspath(filter_dir), 'geo')
ts = datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')

for name in ('full.json', 'normal.json', 'minimal.json'):
    path = os.path.join(geo_dir, name)
    if not os.path.exists(path):
        print(f'  SKIP: {name} не найден')
        continue
    with open(path, encoding='utf-8') as f:
        data = json.load(f)
    data['updated_utc'] = ts
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write('\n')
    print(f'  {name}: updated_utc = {ts}')
