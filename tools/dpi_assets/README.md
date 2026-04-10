# DPI Assets — источник: zapret-linux (апрель 2026)

Файлы получены из сборки zapret (нотмалваре) за 2026-04-10.
Используются для нативной DPI bypass реализации 4eburNet (БЛОК C).

## Файлы

### .bin — fake packet payloads (стратегия C.3 fake+seqovl)

`tls_clienthello_www_google_com.bin` (681 байт)
  Реальный TLS ClientHello захваченный с www.google.com.
  Используется как --dpi-desync-split-seqovl-pattern (seqovl=681).
  В коде: dpi_strategies.c → strategy_fake_split()
  На роутере: /etc/4eburnet/dpi/tls_clienthello_www_google_com.bin

`quic_initial_www_google_com.bin` (1200 байт)
  Реальный QUIC Initial пакет от Google.
  Используется как --dpi-desync-fake-quic payload.
  В коде: dpi_strategies.c → strategy_fake_quic()
  На роутере: /etc/4eburnet/dpi/quic_initial_www_google_com.bin

### Списки (деплоятся на роутер в /etc/4eburnet/dpi/)

`ipset.txt` (~156 KB)
  IP-диапазоны Akamai, Cloudflare, Hetzner, OVH, Oracle, AWS.
  Для этих адресов применять DPI bypass стратегию.
  Использование: dpi_filter.c → dpi_filter_init()

`whitelist.txt` (~31 KB)
  Домены которые работают напрямую через Cloudflare/CDN.
  DPI bypass для них НЕ применять (могут сломаться).
  Использование: dpi_filter.c → dpi_filter_is_whitelisted()

`autohosts.txt` (~1.4 KB)
  Домены для автоматического DPI bypass:
  YouTube, Instagram, Discord, BBC, Telegram и др.
  Использование: dpi_filter.c → начальный hostlist

### Документация

`zapret_strategies_2026-04.txt`
  Рабочие стратегии zapret против ТСПУ (апрель 2026).
  Референс для параметров C.2 (split) и C.3 (fake+seqovl).

## Стратегии (для реализации C.2-C.4)

Параметры из `zapret_strategies_2026-04.txt`:

### TCP 443 (HTTPS) — основная стратегия

```
fake,multisplit
  split-pos    = 1
  seqovl       = 681       (размер tls_clienthello.bin)
  seqovl-pat   = tls_clienthello_www_google_com.bin
  fooling      = ts         (TCP timestamp manipulation)
  repeats      = 8
  fake-tls-mod = rnd,dupsid,sni=www.google.com
  ipset        = ipset.txt  (Cloudflare/Akamai/etc.)
  exclude      = whitelist.txt
```

### UDP 443 (QUIC)

```
fake
  repeats   = 11
  fake-quic = quic_initial_www_google_com.bin
  ipset     = ipset.txt
  exclude   = whitelist.txt
```

### Discord UDP

```
fake
  ports   = 19294-19344, 50000-50100
  l7      = discord, stun
  repeats = 6
```

### Discord TCP (CDN порты)

```
multisplit
  ports    = 2053, 2083, 2087, 2096, 8443
  domains  = discord.media
  seqovl   = 568
  pos      = 1
  seqovl-pat = tls_clienthello_www_google_com.bin
```
