# 4eburNet — Инструкция по сборке

## 1. Требования

### Компиляторы

| Архитектура | Компилятор | SDK |
|---|---|---|
| x86_64 (dev/mini-PC) | `musl-gcc` | `apt install musl-tools` |
| mipsel_24kc (EC330 MT7621A) | `mipsel-openwrt-linux-musl-gcc` | `~/4eburnet-dev/sdk/mipsel-mt7621/` |
| aarch64_cortex-a53 (Flint2) | `aarch64-openwrt-linux-musl-gcc` | `~/4eburnet-dev/sdk/aarch64/` |
| x86_64 OpenWrt (mini-PC) | `x86_64-openwrt-linux-musl-gcc` | `~/4eburnet-dev/sdk/x86_64/` |

### wolfSSL 5.9.0

Версия зафиксирована. Пересобрать с флагами:

```
--enable-all --enable-static-ephemeral --enable-quic --disable-shared
```

Флаги обязательны: `--enable-all` включает Curve25519/HKDF/AES-GCM для Reality TLS
custom stack; `--enable-static-ephemeral` нужен для `wc_curve25519_make_key` при
статической линковке.

Скрипт настройки окружения (скачивает wolfSSL, собирает для всех архитектур,
создаёт симлинки SDK):

```bash
bash scripts/dev-setup.sh
```

Проверка установки:

```bash
bash scripts/dev-setup.sh --check
```

Пути установки:
- x86_64: `/usr/local/musl-wolfssl`
- mipsel: `/usr/local/musl-wolfssl-mipsel`
- aarch64: `/usr/local/musl-wolfssl-aarch64`

### Node.js 22+ (опционально)

Нужен только для пересборки dashboard из исходников (`dashboard-src/`).
Для сборки демона не требуется.

---

## 2. Сборка x86_64 dev

```bash
cd core
make -f Makefile.dev clean && make -f Makefile.dev
```

Результат: `../build/4eburnetd` (stripped, ≤4MB).

Запуск тестов — обязателен перед коммитом:

```bash
make -f Makefile.dev test
# Ожидаемый результат: ALL PASS
```

Профили сборки (по умолчанию `full`):

```bash
make -f Makefile.dev PROFILE=micro   # <64MB RAM: без QUIC/Reality
make -f Makefile.dev PROFILE=normal  # 64-128MB
make -f Makefile.dev PROFILE=full    # 128MB+, все протоколы
```

---

## 3. Кросс-сборка IPK

SDK-пути и версии OpenWrt определяются внутри `scripts/build.sh` через
`SDK_BASE=$HOME/4eburnet-dev/sdk` — хардкод путей не нужен.

```bash
bash scripts/build.sh mipsel    # EC330 MT7621A → build/mipsel/4eburnet_*_mipsel_24kc.ipk
bash scripts/build.sh aarch64   # Flint2 mediatek-filogic → build/aarch64/4eburnet_*_aarch64_cortex-a53.apk
bash scripts/build.sh x86_64    # mini-PC OpenWrt → build/x86_64/4eburnet_*_x86_64.ipk
bash scripts/build.sh all       # все три архитектуры
```

`build.sh` автоматически:
1. Проверяет наличие SDK и запускает `feeds update + defconfig` при первом запуске.
2. Вызывает `make -f Makefile.dev cross-<arch>` если `prebuilt/<arch>/4eburnetd` отсутствует.
3. Копирует результирующий пакет в `build/<arch>/`.

Перед каждой сборкой — очистить stale артефакты (WSL rsync timestamp issue):

```bash
rm -rf ~/4eburnet-dev/project/4eburNet/
rsync -av /mnt/d/Проекты/4eburNet/ ~/4eburnet-dev/project/4eburNet/
cd ~/4eburnet-dev/project/4eburNet/core
make -f Makefile.dev clean
```

---

## 4. Запуск тестов

```bash
make -f core/Makefile.dev test
```

Тест-покрытие (v1.5.5):
- `tests/test_ws_handshake.c` — 4 PASS (RFC 6455 §1.3)
- `tests/test_ws_frame.c` — 7 PASS (RFC 6455 §5.7)
- `tests/reality/` — 32 функции, 6 файлов, roundtrip
- `tests/test_tls13_wire.c` — 60 PASS
- `tests/test_reality_pbk_decode.c` — 12 PASS

---

## 5. Deploy на роутер

Конфиг деплоя (`scripts/deploy.conf`, не в git):

```bash
cp scripts/deploy.conf.example scripts/deploy.conf
# Заполнить ROUTER_IP, ROUTER_PORT, ROUTER_USER, ROUTER_ARCH
```

Деплой:

```bash
export ROUTER_IP=192.168.2.1   # EC330 dev
bash scripts/deploy.sh full    # build + install + restart + logs
```

`deploy.sh` проверяет свободную RAM перед отправкой файлов:
- `< 5MB` → exit 2 (критично: OOM убьёт dropbear)
- `< 15MB` → exit 1 (предупреждение, деплой остановлен)

Деплой на `192.168.1.1` (Flint2) заблокирован в `deploy.sh:44-50`.

Отдельные команды:

```bash
bash scripts/deploy.sh check    # проверка SSH
bash scripts/deploy.sh build    # только сборка
bash scripts/deploy.sh push     # scp IPK → /tmp/
bash scripts/deploy.sh install  # push + opkg install
bash scripts/deploy.sh restart  # /etc/init.d/4eburnet restart
bash scripts/deploy.sh logs     # logread | grep 4eburnet
```

---

## 6. Known limitations

### SIGHUP reload

`handle_reload` реализован и корректен при штатной работе демона.
При зависании event loop (Reality death spiral, актуально до фикса T0-03) —
использовать `/etc/init.d/4eburnet restart` вместо `kill -HUP`.

### /proxies endpoint

Теперь читает runtime-состояние из `proxy_group_state_t` (исправлено в v1.5.5).
Ранее отдавал static config → zashboard видел `all_count=1`.

### http_send_file

Async через EPOLLOUT (исправлено в v1.5.5).
До фикса статические файлы dashboard блокировали event loop на медленных соединениях.
