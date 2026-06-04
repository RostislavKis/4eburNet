# 4eburNet — Сборка и деплой

Версия: v1.5.161 | Архитектуры: mipsel_24kc, aarch64, armv7, x86_64

---

## 1. Требования

### Операционная система

Ubuntu 22.04 / 24.04 (WSL2 или native). На Windows — обязательно WSL2; все команды выполняются внутри WSL.

### Системные зависимости

```bash
sudo apt-get install -y \
    musl-tools \
    build-essential \
    git \
    autoconf \
    automake \
    libtool \
    pkg-config
```

| Пакет | Команда | Назначение |
|-------|---------|------------|
| `musl-tools` | `musl-gcc` | native x86_64 dev build + wolfSSL host |
| `build-essential` | `make`, `gcc` | сборка тестов и инструментов |
| `git` | `git` | клонирование wolfSSL |
| `autoconf`, `automake`, `libtool` | `autoconf`, `libtoolize` | `./autogen.sh` wolfSSL |
| `pkg-config` | `pkg-config` | проверка зависимостей |

Проверить готовность окружения без установки:

```bash
./scripts/dev-setup.sh --check
```

### wolfSSL

Версия: **5.9.0** (`v5.9.0-stable`)

| Архитектура | Путь установки (`WOLFSSL_*`) |
|-------------|------------------------------|
| x86_64 (host dev) | `/usr/local/musl-wolfssl` |
| mipsel (EC330, MT7621A) | `/usr/local/musl-wolfssl-mipsel` |
| aarch64 (Flint2, mini-PC) | `/usr/local/musl-wolfssl-aarch64` |
| armv7 | `/usr/local/musl-wolfssl-armv7` |

### OpenWrt SDK

SDK распакованы в `~/4eburnet-dev/sdk/`:

| Архитектура | SDK путь | GCC |
|-------------|----------|-----|
| mipsel_24kc (MT7621) | `~/4eburnet-dev/sdk/mipsel/sdk-mipsel/` | 12.3.0 |
| aarch64_cortex-a53 | `~/4eburnet-dev/sdk/aarch64/sdk-aarch64/` | 14.3.0 |
| armv7 | `~/4eburnet-dev/sdk/armv7/sdk-armv7/` | 13.3.0 |
| x86_64 | `~/4eburnet-dev/sdk/x86_64/sdk-x86_64/` | 12.3.0 |

Переменные toolchain для кросс-компиляции (`core/Makefile.dev`):

| Переменная | Значение по умолчанию |
|------------|----------------------|
| `TC_MIPSEL` | `~/4eburnet-dev/sdk/mipsel/sdk-mipsel/staging_dir/toolchain-mipsel_24kc_gcc-12.3.0_musl/bin` |
| `TC_AARCH64` | `~/4eburnet-dev/sdk/aarch64/sdk-aarch64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl/bin` |
| `TC_ARMV7` | `~/4eburnet-dev/sdk/armv7/sdk-armv7/staging_dir/toolchain-arm_cortex-a9+neon_gcc-13.3.0_musl/bin` |
| `TC_X86_64` | `~/4eburnet-dev/sdk/x86_64/sdk-x86_64/staging_dir/toolchain-x86_64_gcc-12.3.0_musl/bin` |

Пути переопределяются переменными окружения или через `make -f Makefile.dev TC_MIPSEL=...`.

---

## 2. Установка wolfSSL (однократно)

wolfSSL собирается один раз для каждой архитектуры и устанавливается в системный prefix.

### Автоматическая установка (все архитектуры)

```bash
cd ~/4eburnet-dev/project/4eburNet
./scripts/dev-setup.sh
```

Скрипт пропускает архитектуру если нужный кросс-компилятор не установлен, и пропускает уже установленную версию 5.9.0.

### Ручная установка — x86_64 (host build)

```bash
git clone --depth=1 --branch v5.9.0-stable \
    https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl-src
cd /tmp/wolfssl-src
./autogen.sh

CC=musl-gcc ./configure \
    --prefix=/usr/local/musl-wolfssl \
    --enable-static --disable-shared \
    --enable-all \
    --enable-quic \
    --enable-harden \
    --enable-sp --enable-sp-math-all --enable-fastmath \
    --disable-blake2 --disable-blake2s

make -j"$(nproc)"
sudo make install
rm -rf /tmp/wolfssl-src
```

### Ручная установка — mipsel (EC330 / MT7621A)

```bash
TC_MIPSEL=~/4eburnet-dev/sdk/mipsel/sdk-mipsel/staging_dir/toolchain-mipsel_24kc_gcc-12.3.0_musl

git clone --depth=1 --branch v5.9.0-stable \
    https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl-mipsel
cd /tmp/wolfssl-mipsel
./autogen.sh

CC=$TC_MIPSEL/bin/mipsel-openwrt-linux-musl-gcc \
./configure \
    --prefix=/usr/local/musl-wolfssl-mipsel \
    --host=mipsel-openwrt-linux-musl \
    --enable-static --disable-shared \
    --enable-all \
    --enable-quic \
    --enable-harden \
    --enable-sp --enable-sp-math-all --enable-fastmath \
    --disable-blake2 --disable-blake2s

make -j"$(nproc)"
sudo make install
rm -rf /tmp/wolfssl-mipsel
```

### Ручная установка — aarch64 (Flint2 / mini-PC)

Используй параметризованный скрипт:

```bash
WOLFSSL_SRC=/tmp/wolfssl-aarch64-src
TC_AARCH64=~/4eburnet-dev/sdk/aarch64/sdk-aarch64/staging_dir/toolchain-aarch64_cortex-a53_gcc-14.3.0_musl

git clone --depth=1 --branch v5.9.0-stable \
    https://github.com/wolfSSL/wolfssl.git "$WOLFSSL_SRC"
cd "$WOLFSSL_SRC" && ./autogen.sh && cd -

WOLFSSL_SRC="$WOLFSSL_SRC" \
TC_AARCH64="$TC_AARCH64" \
WOLFSSL_AARCH64=/usr/local/musl-wolfssl-aarch64 \
    ./scripts/wolfssl_build_aarch64.sh
```

### Ручная установка — armv7

```bash
TC_ARMV7=~/4eburnet-dev/sdk/armv7/sdk-armv7/staging_dir/toolchain-arm_cortex-a9+neon_gcc-13.3.0_musl

git clone --depth=1 --branch v5.9.0-stable \
    https://github.com/wolfSSL/wolfssl.git /tmp/wolfssl-armv7
cd /tmp/wolfssl-armv7
./autogen.sh

CC=$TC_ARMV7/bin/arm-openwrt-linux-musleabihf-gcc \
./configure \
    --prefix=/usr/local/musl-wolfssl-armv7 \
    --host=arm-openwrt-linux-musleabihf \
    --enable-static --disable-shared \
    --enable-all \
    --enable-quic \
    --enable-harden \
    --enable-sp --enable-sp-math-all --enable-fastmath \
    --disable-blake2 --disable-blake2s

make -j"$(nproc)"
sudo make install
rm -rf /tmp/wolfssl-armv7
```

### Проверка установки

```bash
./scripts/dev-setup.sh --check
```

Ожидаемый вывод для каждой архитектуры:

```
[OK] [mipsel] libwolfssl.a 4.2M
[OK] [mipsel] wc_curve25519_init присутствует
```

---

## 3. Сборка бинарника

### Рабочий процесс (WSL2 + Windows)

Исходники хранятся на Windows (`D:\4eburNet\`). Перед каждой сборкой синхронизировать в WSL:

```bash
rsync -a --delete /mnt/d/4eburNet/ ~/4eburnet-dev/project/4eburNet/
cd ~/4eburnet-dev/project/4eburNet/core
```

**Никогда не редактировать файлы напрямую в WSL** — при следующем rsync изменения будут перезаписаны.

### Сборка для конкретной архитектуры

```bash
# mipsel (EC330 / MT7621A) — PROFILE=normal
make -f Makefile.dev cross-mipsel

# aarch64 (Flint2 / mini-PC) — PROFILE=full
make -f Makefile.dev cross-aarch64

# armv7 — PROFILE=normal
make -f Makefile.dev cross-armv7

# x86_64 — PROFILE=full
make -f Makefile.dev cross-x86_64
```

Результат: `../prebuilt/<arch>/4eburnetd` (stripped, ≤4MB).

### Native x86_64 dev build (без cross-toolchain)

```bash
make -f Makefile.dev
# Результат: ../../build/4eburnetd
```

### Очистка

```bash
make -f Makefile.dev clean
```

### Переменные окружения сборки

| Переменная | Назначение | Пример |
|------------|-----------|--------|
| `PROFILE` | Профиль функций | `micro` / `normal` / `full` |
| `TC_MIPSEL` | Путь к mipsel toolchain bin/ | `~/4eburnet-dev/sdk/mipsel/.../bin` |
| `TC_AARCH64` | Путь к aarch64 toolchain bin/ | `~/4eburnet-dev/sdk/aarch64/.../bin` |
| `TC_ARMV7` | Путь к armv7 toolchain bin/ | `~/4eburnet-dev/sdk/armv7/.../bin` |
| `TC_X86_64` | Путь к x86_64 toolchain bin/ | `~/4eburnet-dev/sdk/x86_64/.../bin` |
| `WOLFSSL_MIPSEL` | wolfSSL prefix для mipsel | `/usr/local/musl-wolfssl-mipsel` |
| `WOLFSSL_AARCH64` | wolfSSL prefix для aarch64 | `/usr/local/musl-wolfssl-aarch64` |
| `WOLFSSL_ARMV7` | wolfSSL prefix для armv7 | `/usr/local/musl-wolfssl-armv7` |
| `WOLFSSL_X86_64` | wolfSSL prefix для x86_64 | `/usr/local/musl-wolfssl` |
| `EBURNET_VERSION` | Версия (передаётся как -D) | `1.5.161` |
| `EXTRA_CFLAGS` | Дополнительные флаги компилятора | `-O3` |
| `PREBUILT_DIR` | Куда кладётся stripped бинарник | `../prebuilt` |

### Профили сборки (PROFILE)

| Профиль | RAM устройства | Отличия |
|---------|---------------|---------|
| `micro` | <64 MB | Fake-IP выкл, PROXY_PROVIDERS выкл, ShadowTLS выкл |
| `normal` | 64–128 MB | Все протоколы, gRPC multiplex включён |
| `full` | >128 MB | Всё включено; используется по умолчанию для aarch64/x86_64 |

### AddressSanitizer (отладка)

```bash
make -f Makefile.dev asan
# Требует gcc (не musl-gcc); UBSan + ASan
```

---

## 4. Сборка IPK пакета

IPK собирается через OpenWrt SDK по схеме «prebuilt binary → IPK»: бинарник из `prebuilt/` упаковывается SDK без перекомпиляции.

### Настройка SDK (однократно)

`scripts/build.sh` создаёт symlink `$SDK/package/4eburnet → $PROJECT_DIR` автоматически.

Если SDK не инициализирован (`$SDK/.config` отсутствует`), скрипт запускает:

```bash
cd $SDK
./scripts/feeds update -a
./scripts/feeds install -a
make defconfig
```

### Сборка IPK

```bash
cd ~/4eburnet-dev/project/4eburNet

# Одна архитектура:
./scripts/build.sh mipsel       # EC330 (MT7621A) → mipsel_24kc
./scripts/build.sh aarch64      # Flint2 / mini-PC
./scripts/build.sh x86_64       # x86_64 OpenWrt

# Все три:
./scripts/build.sh all

# Очистка:
./scripts/build.sh clean
```

Артефакты: `build/<arch>/4eburnet_<PKG_VERSION>_<openwrt_arch>.ipk`

`PKG_VERSION` берётся из корневого `Makefile` (строка `PKG_VERSION:=`).

### Переопределение SDK путей

```bash
MIPSEL_SDK=/path/to/sdk ./scripts/build.sh mipsel
AARCH64_SDK=/path/to/sdk ./scripts/build.sh aarch64
X86_64_SDK=/path/to/sdk ./scripts/build.sh x86_64
```

---

## 5. Сборка dashboard (zashboard)

Dashboard (`dashboard-src/`) — форк zashboard v3.5.0. Собирается отдельно.

```bash
cd ~/4eburnet-dev/project/4eburNet/dashboard-src
npm install
npm run build
```

Результат: `dashboard-src/dist/` — статические файлы.

Копирование в пакет (выполняется скриптом postinstall автоматически при IPK установке):

```bash
cp -r dist/* /usr/share/4eburnet/dashboard/
```

Dashboard раздаётся демоном на порту `:8080`. Для обновления без пересборки бинарника достаточно заменить файлы в `/usr/share/4eburnet/dashboard/` на роутере.

---

## 6. Запуск тестов

Тесты компилируются с теми же security guards что и production (`-fstack-protector-strong`, `-D_FORTIFY_SOURCE=2`, `-Werror`).

```bash
cd ~/4eburnet-dev/project/4eburNet/core
make -f Makefile.dev test
```

42 тестовых суита. Ожидаемый результат:

```
Status:   OK        ← каждый суит
Status:   ALL PASS  ← финальная строка
```

Отдельные суиты:

```bash
make -f Makefile.dev test-uri          # Hysteria2 URI парсинг
make -f Makefile.dev test-reality-auth # Reality TLS аутентификация
make -f Makefile.dev test-ws-frame     # WebSocket framing RFC 6455
make -f Makefile.dev test-dpi-strategy # DPI стратегии обхода
make -f Makefile.dev test-geo-bin      # Geo базы .gbin формат
# ... см. make -f Makefile.dev help для полного списка
```

Тест `Reality verify: cert_extract FAIL cert_len=64` при запуске `test-reality-auth` — штатное поведение: он проверяет отказ на не-X.509 данных.

---

## 7. Деплой на EC330 (разработка)

EC330: dev-роутер, 192.168.2.1, root, пароль `openwrt1`.

**Не путать с Flint2 (192.168.1.1) — продакшн роутер, деплой запрещён.**

### Полный цикл

```bash
# 1. Синхронизация исходников Windows → WSL
rsync -a --delete /mnt/d/4eburNet/ ~/4eburnet-dev/project/4eburNet/

# 2. Кросс-компиляция
cd ~/4eburnet-dev/project/4eburNet/core
make -f Makefile.dev cross-mipsel

# 3. Остановить демон и удалить старый бинарник на роутере
#    (без rm -f → Text file busy при scp)
ssh root@192.168.2.1 '/etc/init.d/4eburnet stop; sleep 1; rm -f /usr/sbin/4eburnetd'

# 4. Копирование (флаг -O: legacy SCP mode, OpenWrt не имеет sftp-server)
scp -O ~/4eburnet-dev/project/4eburNet/prebuilt/mipsel/4eburnetd \
    root@192.168.2.1:/usr/sbin/4eburnetd

# 5. Запуск
ssh root@192.168.2.1 'chmod +x /usr/sbin/4eburnetd && /etc/init.d/4eburnet start'

# 6. Проверка
ssh root@192.168.2.1 'logread | tail -20'
```

### Через deploy.sh (если настроен)

```bash
# Создать конфиг из примера:
cp scripts/deploy.conf.example scripts/deploy.conf
# Заполнить: ROUTER_IP, SSH_KEY, BINARY_SRC

./scripts/deploy.sh check    # проверить соединение
./scripts/deploy.sh deploy   # остановить → скопировать → запустить
./scripts/deploy.sh logs     # logread -f
./scripts/deploy.sh shell    # SSH в роутер
```

`deploy.sh` защищён от случайного деплоя на `192.168.1.1` (Flint2) — при попытке выходит с кодом 99.

### UCI настройки после первого деплоя

```bash
uci set 4eburnet.dns.fake_ip_enabled='1'
uci set 4eburnet.dns.doh_url='https://dns.google/dns-query'
uci set 4eburnet.dns.doh_ip='8.8.8.8'
uci set 4eburnet.dns.upstream_default='8.8.8.8'
uci commit 4eburnet
/etc/init.d/4eburnet restart
```

### SSH ключ в WSL

```bash
cp /mnt/c/Users/Rosti/.ssh/id_ed25519 /tmp/ec330_key
chmod 600 /tmp/ec330_key
ssh -i /tmp/ec330_key root@192.168.2.1
```

---

## 8. Troubleshooting

### `$(error TC_MIPSEL не найден: ...)`

SDK toolchain не найден по пути `TC_MIPSEL`. Проверить:

```bash
ls ~/4eburnet-dev/sdk/mipsel/sdk-mipsel/staging_dir/
# Должны быть каталоги toolchain-mipsel_24kc_*/
```

Путь переопределяется:

```bash
make -f Makefile.dev cross-mipsel \
    TC_MIPSEL=/path/to/toolchain/bin
```

### `$(error WOLFSSL_MIPSEL не найден: /usr/local/musl-wolfssl-mipsel)`

wolfSSL не установлен для этой архитектуры. Выполнить установку из раздела 2.

Проверить:

```bash
ls /usr/local/musl-wolfssl-mipsel/lib/libwolfssl.a
```

### `warning: environment variable 'STAGING_DIR' not defined`

Предупреждение от OpenWrt toolchain wrapper — не ошибка. Сборка продолжается корректно. Для подавления:

```bash
export STAGING_DIR=~/4eburnet-dev/sdk/mipsel/sdk-mipsel/staging_dir
make -f Makefile.dev cross-mipsel
```

### `Text file busy` при scp

Демон запущен и держит файл `/usr/sbin/4eburnetd`. Сначала остановить:

```bash
ssh root@192.168.2.1 '/etc/init.d/4eburnet stop; sleep 1; rm -f /usr/sbin/4eburnetd'
```

Затем повторить scp.

### SSH timeout при подключении к EC330

Не означает падение роутера. Проверить:

```bash
ping 192.168.2.1
# Если ping проходит — роутер жив, возможно перезапускается демон dropbear
```

Подождать 10–15 секунд, попробовать снова. Если ping не проходит — проверить кабель и IP-адрес.

### Бинарник >4 MB

Размер не должен превышать 4MB для MIPS устройств с 32MB flash. Проверить профиль:

```bash
# Для mipsel используется PROFILE=normal (не full)
make -f Makefile.dev cross-mipsel PROFILE=normal
ls -lh ../prebuilt/mipsel/4eburnetd
```

Если >4MB с `normal` — проверить наличие `-flto` и `--gc-sections` в CFLAGS (они включены по умолчанию).

### Тест FAIL

```bash
# Запустить конкретный тест с verbose выводом:
make -f Makefile.dev test-reality-auth
# или напрямую:
/tmp/test_reality_auth
```

`Reality verify: cert_extract FAIL cert_len=64` — штатно, не баг.

---

## Структура артефактов

```
prebuilt/
├── mipsel/4eburnetd    — EC330 (MT7621A, stripped, PROFILE=normal)
├── aarch64/4eburnetd   — Flint2 / mini-PC (stripped, PROFILE=full)
├── armv7/4eburnetd     — средние роутеры (stripped, PROFILE=normal)
└── x86_64/4eburnetd    — x86_64 OpenWrt (stripped, PROFILE=full)

build/<arch>/
└── 4eburnet_<version>_<openwrt_arch>.ipk
```
