# 4eburNet — Правила деплоя

## АБСОЛЮТНОЕ ПРАВИЛО WORKFLOW

**WSL — ТОЛЬКО для компиляции. Всё остальное — Windows.**

| Действие | Инструмент |
|----------|-----------|
| Редактирование кода | File tools → D:\Проекты\4eburNet\ |
| Компиляция | `wsl bash -c "cd '/mnt/d/Проекты/4eburNet/core' && make mipsel"` |
| Деплой бинарника | Windows: `scp -O D:\...\4eburnetd root@192.168.2.1:/usr/sbin/` |
| SSH на роутер | Windows SSH: `ssh root@192.168.2.1` |
| Git | Windows PowerShell в D:\Проекты\4eburNet\ |

**rsync ЗАПРЕЩЁН. Никогда. Ни при каких условиях.**

---

## КРИТИЧЕСКИ ВАЖНО: деплой ТОЛЬКО с Windows

UCI-скрипты и бинарники деплоятся **ТОЛЬКО через Windows**.
Никогда не через WSL напрямую.

### Причина
WSL 2 работает в изолированной сети (NAT). Роутер 192.168.2.1 (EC330)
и 192.168.1.1 (Flint2) недоступны из WSL напрямую. SSH/SCP из WSL
не достигает 192.168.x.x — соединение зависает или сбрасывается.
Использовать только PowerShell или cmd на хосте.

---

## Деплой бинарника (Windows PowerShell)

```powershell
# 1. Собрать в WSL (читает /mnt/d/ напрямую — rsync не нужен)
wsl bash -c "cd '/mnt/d/Проекты/4eburNet/core' && make clean -f Makefile.dev && make -f Makefile.dev cross-mipsel"
# Бинарник появляется автоматически: D:\Проекты\4eburNet\prebuilt\mipsel\4eburnetd

# 2. Остановить демон и удалить старый бинарник (иначе: Text file busy)
ssh root@192.168.2.1 "killall 4eburnetd 2>/dev/null; sleep 2; rm -f /usr/sbin/4eburnetd"

# 3. Скопировать новый бинарник на роутер (-O legacy SCP, OpenWrt без sftp-server)
scp -O D:\Проекты\4eburNet\prebuilt\mipsel\4eburnetd root@192.168.2.1:/usr/sbin/4eburnetd

# 4. Права и запуск
ssh root@192.168.2.1 "chmod +x /usr/sbin/4eburnetd && /etc/init.d/4eburnet start"
```

---

## Деплой UCI (применение конфигурации)

UCI-скрипт генерируется как shell-скрипт (`sh`) с `uci import` внутри.
Применять через `sh`, а не через `uci import` напрямую.

```powershell
# 1. Сгенерировать UCI из config.yaml
python tools\sub_convert.py -i D:\Проекты\4eburNet\config.yaml `
    -o D:\Проекты\4eburNet\generated_uci.sh

# 2. Проверить что main секция есть в начале файла
Select-String "uci set 4eburnet.main=" D:\Проекты\4eburNet\generated_uci.sh

# 3. Создать бэкап текущего конфига
ssh root@192.168.2.1 "uci export 4eburnet > /tmp/4eburnet_backup.uci"

# 4. Скопировать и применить
scp -O D:\Проекты\4eburNet\generated_uci.sh root@192.168.2.1:/tmp/
ssh root@192.168.2.1 "sh /tmp/generated_uci.sh && /etc/init.d/4eburnet restart"
```

---

## Восстановление после сбоя uci import

Если демон не запускается после UCI деплоя — скорее всего потеряна
секция `config 4eburnet 'main'` с `enabled='1'`.

```bash
# На роутере: восстановить main секцию
uci set 4eburnet.main='4eburnet'
uci set 4eburnet.main.enabled='1'
# DNS upstream (если ya.ru не резолвится через 127.0.0.1):
uci set 4eburnet.dns.upstream_bypass='1.1.1.1'
uci set 4eburnet.dns.doh_url='https://dns.google/dns-query'
uci set 4eburnet.dns.doh_ip='8.8.8.8'
uci set 4eburnet.dns.upstream_default='8.8.8.8'
uci commit 4eburnet
/etc/init.d/4eburnet restart
```

Диагностика: `tail -20 /tmp/4eburnet.log`
- `Демон отключён в конфиге, завершение` → нет `main.enabled='1'`
- `upstream не настроен для action 0` → нет `dns.upstream_bypass`

---

## Чеклист после каждого деплоя UCI

```bash
# На роутере — обязательные проверки:
uci show 4eburnet | grep "main.enabled"          # должно быть = '1'
uci show 4eburnet | grep '@traffic_rule\[' | grep '\.type=' | wc -l  # > 300
uci show 4eburnet | grep "type='and'" | wc -l    # > 20
nslookup ya.ru 127.0.0.1                          # реальный IP (не fake-IP)
nslookup google.com 127.0.0.1                     # 198.18.0.x (fake-IP)
nslookup t.me 127.0.0.1                           # 198.18.0.x (fake-IP)
nslookup doubleclick.net 127.0.0.1               # NXDOMAIN (adblock)
grep VmRSS /proc/$(cat /var/run/4eburnet.pid)/status  # < 20MB
```

---

## Geo базы (обновление)

```powershell
# Запустить из Windows PowerShell:
powershell -ExecutionPolicy Bypass `
    -File D:\Проекты\4eburNet\scripts\geo_update_repos.ps1 `
    -Profile full -FilterRepo D:\Проекты\filter

# Затем на роутере передать новые .gbin:
# scp -O D:\Проекты\4eburNet\geo\*.gbin root@192.168.2.1:/etc/4eburnet/geo/
# ssh root@192.168.2.1 "kill -HUP $(cat /var/run/4eburnet.pid)"
```

---

## Известные ловушки (gotchas)

| Проблема | Причина | Решение |
|----------|---------|---------|
| `Text file busy` при scp | Демон держит бинарник открытым | `killall 4eburnetd && rm -f /usr/sbin/4eburnetd` перед scp |
| `Демон отключён в конфиге` | `uci import` стёр `main.enabled` | Восстановить `uci set 4eburnet.main.enabled='1'` |
| `upstream не настроен` | Потеряна `dns.upstream_bypass` | Установить `uci set 4eburnet.dns.upstream_bypass='1.1.1.1'` |
| ya.ru → No answer | Неправильный `upstream_bypass` | Проверить `uci show 4eburnet.dns` |
| `not running` сразу после start | procd не нашёл `main.enabled` | Добавить `uci set 4eburnet.main='4eburnet'` и `enabled='1'` |
| `active with no instances` | То же что выше | То же решение |
| prebuilt/mipsel в Windows — старый | Старый workflow с rsync | WSL пишет напрямую в /mnt/d/ — бинарник сразу в D:\Проекты\4eburNet\prebuilt\mipsel\ |

---

## AWG / AmneziaWireGuard — требования к серверу

### Почему Cloudflare WARP не работает из России

ТСПУ блокирует WireGuard UDP handshake по сигнатуре (с ~2024).
Cloudflare WARP не поддерживает AmneziaWG обфускацию (jc/jmin/jmax/h1-h4).
Результат: handshake_initiation уходит, ответа нет.

### Требования к AWG серверу

- VPS за пределами РФ (Финляндия, Германия, Нидерланды, etc.)
- Поддержка AmneziaWG протокола с обфускацией
- Открытый UDP порт (51820 или любой другой)

### Быстрый деплой AmneziaWG сервера (Ubuntu 22.04)

```bash
# На VPS:
curl -fsSL https://get.docker.com | sh
docker run -d --name amnezia-awg \
  --cap-add NET_ADMIN --cap-add SYS_MODULE \
  -v /opt/amnezia:/opt/amnezia \
  -p 51820:51820/udp --restart unless-stopped \
  amneziavpn/amnezia-awg:latest

# Получить конфиг клиента:
docker exec amnezia-awg awg-quick-add-client ec330
docker exec amnezia-awg cat /opt/amnezia/clients/ec330.conf
```

### UCI настройка после получения конфига

```bash
# На EC330 (из Windows PowerShell):
ssh root@192.168.2.1 "
uci set 4eburnet.@server[N].awg_jc='5'
uci set 4eburnet.@server[N].awg_jmin='100'
uci set 4eburnet.@server[N].awg_jmax='500'
uci set 4eburnet.@server[N].awg_h1='1'
uci set 4eburnet.@server[N].awg_h2='2'
uci set 4eburnet.@server[N].awg_h3='3'
uci set 4eburnet.@server[N].awg_h4='4'
uci commit 4eburnet
"
```

### Статус: BLOCKED — нужен VPS

Код AWG реализован полностью (v1.5.x).
Нужен только endpoint с поддержкой AmneziaWG.
