# 4eburNet Master Roadmap

> Версия: **v2.5.83** · Дата: 2026-05-30
> Статус: активная разработка · ~90 000+ LoC · EC330 продакшн · AWG WARP handshake ✅ · Telegram через AmneziaWG стабильно · 531 KB/s · двухфазный HC

---

## Vision

**4eburNet** — самый компактный, быстрый и универсальный proxy/routing демон для OpenWrt. Единственный бинарь **заменяющий mihomo + podkop + xray + dnscrypt + ruleset manager**. Лучше во всех измерениях — размер, скорость, фичи, UX, надёжность.

### Competitive landscape

| Проект | Язык | Бинарник | GC | Фичи |
|---|---|---|---|---|
| **mihomo** | Go | ~60 MB | Да | Reference, все протоколы, тяжёлый |
| **sing-box** | Go | ~25 MB | Да | Мультипротокол, разрозненный UI |
| **Xray** | Go | ~30 MB | Да | Server-centric, не для embedded |
| **podkop** | Shell | small | Нет | Delegates в другие пакеты |
| **4eburNet** | C23+musl+wolfSSL | **3.2 MB** | Нет | All-in-one, native DPI, NewReno CC, AWG userspace |

### 4eburNet differentiators

1. **3.2 MB статический бинарь** — 18× меньше mihomo, ноль зависимостей
2. **C23 + musl + wolfSSL** — no Go runtime, no GC pauses, native memory control
3. **epoll ET single-thread** — предсказуемая latency vs goroutines
4. **Single package** заменяет mihomo + podkop + xray + dnscrypt
5. **Нативный Adaptive DPI bypass** встроенный (zapret/tpws не нужен)
6. **Zashboard UI + LuCI integration** out-of-box
7. **AnyTLS с адаптивным RTT-aware padding** — anti-fingerprinting на уровне TLS record sizes
8. **TUIC v5 с NewReno CC** — адаптивный congestion control
9. **Per-device routing / per-MAC isolation** нативно
10. **AmneziaWireGuard** — полный WG + junk packets + userspace IPv4/TCP ipstack без kmod

---

## Текущее состояние (2026-05-31, v2.5.92)

**Codebase**: ~90 000+ LoC sources (core + tests + tools + luci)
**Бинарники**: mipsel 3.2MB / aarch64 ~2.1MB / x86_64 ~5.0MB — все stripped, статические
**Unit tests**: 1391 PASS, 0 FAIL
**Целевые платформы**: EC330 (128MB RAM, mipsel_24kc), Flint2 (512MB, aarch64)
**audit_v53**: ✅ ЗАКРЫТ (v2.5.86–v2.5.92) — 2 блокера + 7 проблем + 5 замечаний (§5 WONTFIX обоснован). Критический путь к v3.0.0 открыт.

### Что реально работает (полная реализация)

**Транспортный стек** — все T0 закрыты:
- **VLESS Reality** (tls13_hs.c + reality_auth.c, ~2632 LoC) — custom TLS 1.3 stack, x25519, AES-256-GCM, HKDF
- **XTLS Vision** (vision.c 625 LoC) — XTLS-rprx-vision addons, TLS record boundary detection
- **Trojan + Reality** — полный Reality путь для Trojan (v2.5.43), relay_proto-aware dispatch
- **gRPC** (~780 LoC + h2.c) — HTTP/2, HPACK decoder RFC 7541, flow control, multiplex pool 32 conn × 16 streams
- **WebSocket** (ws_client.c RFC6455) — PING/PONG, CSPRNG masking, 64-bit extended length, CLOSE frame
- **XHTTP/SplitHTTP** (~390 LoC) — HTTP/2 ALPN, immediate recv, chunked streaming
- **HTTPUpgrade** (~110 LoC) — буферизованное чтение + memmem header detection
- **Hysteria2** (1765 LoC) — QUIC, Salamander XOR, Brutal CC, UDP datagrams, per-level flush
- **AnyTLS** (~1400 LoC) — adaptive RTT-aware padding, single-RTT coalesce, SHA256 auth, idle pool
- **TUIC v5** (~2100 LoC) — QUIC v1, TLS-Exporter token, NewReno CC, DATAGRAM 0x30, multi-bidi stream pool
- **VMess AEAD** (~1800 LoC) — AES-128-GCM чанки, SHAKE-128 ChunkMasking, AesCbc(iv=0) AuthID
- **Shadowsocks 2022** (469 LoC + hc_ss.c) — 2022-blake3-chacha20-poly1305 / aes-128/256-gcm, AEAD chunk framing
- **ShadowTLS v3** (341 LoC) — HMAC-SHA256 SessionID, AppData HMAC chain, ClientHello парсинг
- **AmneziaWireGuard** (awg.c + awg_pool.c + awg_ipstack.c) — Noise IK (blake2s HMAC verified, curve25519, ChaCha20-Poly1305 incremental API), обфускация Jc/Jmin/Jmax/H1-H4/CPS, singleton peer pool, автоматический rekey, userspace IPv4/TCP стек
- **Mux.Cool/XUDP** (1064 LoC) — transport-agnostic I/O, GlobalID BLAKE3, UDP relay

**AWG статус** (v2.5.60):
- Handshake ✅ — blake2s sigma[9] fix, wolfSSL incremental AEAD, reserved=00 в Init
- Transport ✅ — IP/TCP checksum network-order, 16-byte WG padding, Windows SYN fingerprint
- Rekey ✅ — автоматический через 180с, noise_encrypt expire sync
- Throughput ✅ — 531 KB/s backpressure to_client_buf+EPOLLOUT (v2.5.58)
- HC двухфазный ✅ — WG handshake + inner TCP probe 1.1.1.1:80 (v2.5.60)
- Telegram ✅ — стабильно, нет reconnect storm, плохие серверы исключены
- Фаза 3 ✅ — delayed ACK (v2.5.84): bulk 115→209 KB/s (+82%), MTProto ≤500B immediate
- Lever A ✅ — stream lookup O(1) hash 256B (v2.5.85): 162 конк. потока, scalability
- T1-AWG-throughput CLOSED — потолок = server-cwnd WARP, не роутер (демон 2% CPU median)

**DNS**: fake-IP v4+v6, Cookie RFC 9018, PTR resolver, AAAA NODATA, AD bit, stale-while-revalidate, DoH/DoT/DoQ, DnsPolicy fallback chain

**Routing**: TPROXY, 300K+ CIDR Verdict Maps O(1), GeoIP/GeoSite .gbin + Bloom filter, nftables Flow Offload (flowtable eburnet_ft), TC Fast Path 0x20, per-MAC device routing

**Crypto**: wolfSSL 5.9.0, BLAKE2s HMAC (ipad/opad), curve25519-donna, Noise IK (AWG), Reality AES-256-GCM, JA3/JA4 fingerprinting

**Infrastructure**: Zashboard v3.5.0 fork (vanilla JS), 14 IPC commands, Adaptive DPI + JA3/JA4, proxy groups с pinned selection, batch HC, url-test, load-balance, AND rule builder, LuCI Enhanced, CI/CD GitHub Actions, sub_convert.py, cdn_updater

---

## Tier 0 — CRITICAL UNBLOCK ✅ ЗАВЕРШЁН

| Задача | Статус | Версия |
|--------|--------|--------|
| T0-01 VLESS Reality params parser | ✅ DONE | v1.5.5 |
| **T0-01a Trojan+Reality+gRPC** | ✅ DONE | v2.5.43 |
| T0-02 XTLS Vision encoder | ✅ DONE | v2.3.6 |
| T0-03 gRPC transport + h2.c | ✅ DONE | v1.5.32–1.5.148 |
| T0-04 WebSocket transport RFC6455 | ✅ DONE | v1.5.62, 1.5.149–150 |
| T0-05 XHTTP/SplitHTTP | ✅ DONE | v1.5.63, 1.5.151–153 |
| T0-06 HTTPUpgrade | ✅ DONE | v1.5.64, 1.5.154 |
| T0-07 Hysteria2 completion | ✅ DONE | v1.5.65, 1.5.155–156 |
| T0-08 SIGHUP reload | ✅ DONE | v1.5.67 |
| AmneziaWireGuard — handshake + transport | ✅ DONE | v2.5.0 + v2.5.45–v2.5.57 |

---

## Tier 1 — FEATURE PARITY

**Цель**: "Любая конфигурация mihomo работает в 4eburNet."

### Завершённые Tier 1

| Задача | Статус | Версия |
|--------|--------|--------|
| T1-01 Proxy-providers URL fetch | ✅ DONE | v1.5.x |
| T1-02 Rule-providers URL fetch | ✅ DONE | v1.5.x |
| T1-03 GeoIP бинарный формат .gbin | ✅ DONE | v1.5.x |
| T1-04 GeoSite полный (v2fly lists) | ✅ DONE | v1.5.x |
| T1-05 Sniffer TLS SNI | ✅ DONE | v1.5.x |
| T1-06 Sniffer HTTP Host | ✅ DONE | v2.5.23 |
| T1-07 Sniffer QUIC SNI | ✅ DONE | v2.3.29 |
| T1-08 VMess AEAD | ✅ DONE | v2.5.19 |
| T1-09 TUIC v5 | ✅ DONE | v1.5.170–173 |
| T1-10 Hysteria2 completion | ✅ DONE | v1.5.155–156 |
| T1-12 Shadowsocks 2022 | ✅ DONE | v2.5.20 |
| T1-13 XUDP live verification | ✅ DONE | v2.5.32 |
| T1-16 SOCKS5 inbound | ✅ DONE | v2.5.27 |
| T1-17 HTTP inbound | ✅ DONE | v2.5.27 |
| T1-18 DNS policy fallback | ✅ DONE | v2.5.7 |
| T1-20 PUT /proxies/{group} manual select | ✅ DONE | v1.5.26 |
| T1-21 Latency /delay tests | ✅ DONE | v1.5.14, 1.5.109 |
| T1-22 sub_convert.py | ✅ DONE | v2.5.31 |
| T1-23 Clash YAML parser | ✅ DONE | v2.3.29 |
| T1-24 WS /memory /traffic /logs streams | ✅ DONE | v1.5.x |
| T1-25 Per-device traffic logs | ✅ DONE | v2.5.30 |
| T1-26 Graceful reload | ✅ DONE | v2.5.26 |
| DNS Cookie RFC 7873+9018 | ✅ DONE | v1.5.1 |
| PTR resolver RFC 1035 | ✅ DONE | v1.5.1 |
| Pinned proxy group selection | ✅ DONE | v1.5.143 |

### Открытые Tier 1

#### T1-11 ShadowTLS v3 [PARTIAL — код есть]
Инфраструктура готова. Нужна финальная активация + live test на EC330.

#### T1-LuCI-full LuCI полный UI [PARTIAL]
Базовый LuCI Enhanced сделан (v2.4.2): Overview/Settings/Logs + Dashboard link. Остаётся: полные редакторы Servers/Groups/Rules/DNS/Routing в LuCI без :8080.

#### T1-AWG-throughput AWG скорость [CLOSED v2.5.85]
Фаза 1+2+3 + Lever A закрыты. Потолок одного потока (~366 KB/s) — server-cwnd WARP, не роутер.

| Фаза | Описание | Статус |
|------|----------|--------|
| 0 | Baseline 6–50 KB/s измерен | ✅ |
| 1 | Backpressure to_client_buf+EPOLLOUT → 531 KB/s | ✅ v2.5.58 |
| 2 | SO_RCVBUF 4MB + SYN-ACK timeout 5s | ✅ v2.5.59 |
| 3 | Delayed ACK (2×MSS или 40мс) | ✅ v2.5.84 (+82%) |
| 4 | SYN-ACK parsing remote_mss | PENDING (низкий приоритет) |
| 5 | writev() coalescing | ✗ CLOSED — backpressure не лимит (EPOLLOUT 0.03/с) |
| A | stream lookup O(1) hash 256B | ✅ v2.5.85 (162 конк. потока) |

> Потолок одного AWG-потока (~366 KB/s) — server-cwnd WARP, не роутер.
> Агрегат ~800 KB/s при 4 потоках. Локальные оптимизации исчерпаны.
> Следующий рычаг: T3-04 benchmarks vs mihomo / смена WARP-tier.

---

## Tier 2 — DIFFERENTIATORS

**Цель**: "4eburNet делает вещи которые никто другой не делает (или делает значительно лучше)."

### Завершённые Tier 2

| Задача | Статус | Версия |
|--------|--------|--------|
| AnyTLS adaptive RTT-aware padding | ✅ DONE | v2.3.29 |
| TUIC v5 NewReno CC | ✅ DONE | v1.5.173 |
| TC Fast Path mark 0x20 | ✅ DONE | v1.5.x |
| Adaptive DPI + JA3/JA4 + ECH | ✅ DONE | v1.5.x |
| nftables Flow Offload | ✅ DONE | v2.5.8 |
| GeoIP/GeoSite Bloom filter SIMD | ✅ DONE | v1.5.x |
| geo wolfSSL fetch | ✅ DONE | v2.5.6 |
| geoip-ru.gbin mmap | ✅ DONE | v2.5.3 |
| T2-04 BBR CC (TUIC v5 BBR v1/v2) | ✅ DONE | v2.5.22 |
| T2-02 Per-device routing UI | ✅ DONE | v2.5.24 |
| T2-01 Native DPI bypass (5 стратегий) | ✅ DONE | v2.5.25 |

### Открытые Tier 2

#### T2-03 eBPF для Flint2 (aarch64) [NONE]
CO-RE для cross-kernel. Только Flint2 (512MB aarch64). Требует согласования архитектуры.

#### T2-05 Graceful hot reload [NONE]
SIGHUP reload работает, но рвёт все relay соединения. Нужна hot migration relay → new config.

---

## Tier 3 — POLISH & RELEASE

### Завершённые Tier 3

| Задача | Статус | Версия |
|--------|--------|--------|
| T3-01 LuCI Enhanced | ✅ DONE | v2.4.2 |
| T3-02 Test coverage >80% | ✅ DONE | v2.4.5–v2.4.8 |
| T3-03 CI/CD GitHub Actions | ✅ DONE | v2.4.1 |
| T-AND-01 AND rule builder | ✅ DONE | v2.4.3–v2.4.4 |
| T-LB-01 Load-balance стратегии | ✅ DONE | v2.4.3–v2.4.4 |

### Открытые Tier 3

| Задача | Описание | Статус |
|--------|----------|--------|
| T3-04 | Performance benchmarks vs mihomo/ssclash | NONE |
| **T3-05** | **Public release v3.0.0** | **PLANNED** |

### Критический путь к v3.0.0

```
✅ T1-08 VMess AEAD (v2.5.19)
✅ T1-12 SS2022 (v2.5.20)
✅ AWG handshake + transport (v2.5.45–v2.5.57)
    → T1-AWG-throughput (в работе)
        → T3-04 Benchmarks
            → Финальный audit_v53
                → T3-05 tag v3.0.0 + GitHub Release
```

---

## Tech debt (backlog → v3.1.0)

Не блокируют v3.0.0:

| # | Файл | Проблема |
|---|------|---------|
| 1 | nftables.c | `exec_cmd_contains("flowtable")` — loose check |
| 2 | nftables.c | `get_wan_iface()` использует `popen()` |
| 3 | NetworkConfig.vue | BBR/MTU используют нативный `title=` вместо `v-tooltip` |
| 4 | ConnectionTable.vue | JA3/JA4 заголовки без tooltip |
| 5 | dashboard-src | JS chunk 2.15MB > 500KB — нужен code-splitting |
| 6 | awg_ipstack.c | TCP throughput vs ssclash — userspace vs kernel network stack |

---

## Dependency graph

```
T0-03 gRPC + h2.c ─────────────────→ ✅ DONE
T0-04 WS ──────────────────────────→ ✅ DONE
T0-05 XHTTP + T0-06 HTTPUpgrade ───→ ✅ DONE
Hysteria2 QUIC layer ──────────────→ T1-09 TUIC v5 ✅ DONE
Reality TLS stack ─────────────────→ ✅ DONE
AnyTLS padding engine ─────────────→ T2-06 AnyTLS RTT-aware ✅ DONE
TUIC NewReno CC ───────────────────→ T2-04 BBR ✅ DONE
AWG blake2s HMAC + Noise IK ───────→ ✅ DONE v2.5.45
AWG transport + userspace TCP ─────→ ✅ DONE v2.5.52 (throughput в работе)
T1-08 VMess AEAD ──────────────────→ ✅ DONE v2.5.19
T1-12 SS2022 ──────────────────────→ ✅ DONE v2.5.20
T1-AWG-throughput ─────────────────→ T3-04 Benchmarks → T3-05 v3.0.0
```

---

## Архив закрытых задач

### Audits

| Audit | Version | Result |
|-------|---------|--------|
| audit_v42 | v1.5.0 | 0/0/0 |
| audit_v47 | v1.5.163 | 5/6/8 → 0/0/0 |
| audit_v49 | v2.3.25 | 0/0/0 (§1–§43) |
| audit_v50 | v2.4.0 | 14/29/36 → 0/0/0 |
| audit_v51 | v2.5.2 | muxcool/TUIC/AnyTLS debt → 0/0/0 |
| audit_v52 | v2.5.18 | 7/27/19 → 0 блокеров |
| audit_v53 | v2.5.92 | 2/7/5 → 0 блокеров (§5 valid_ifname WONTFIX) |

### AWG history (ключевые фиксы)

| Версия | Фикс |
|--------|------|
| v2.5.0 | blake2s_hmac HMAC (ipad/opad), MixKey KDF1, singleton pool, ipstack |
| v2.5.41 | reserved=00 в Init, skip_awg guard убран |
| v2.5.44 | TAI64N nanoseconds по amneziawg-go reference |
| v2.5.45 | blake2s sigma[9] swap fix — Noise IK KDF корректен |
| v2.5.46 | wolfSSL incremental AEAD — hs_done=1, handshake завершается |
| v2.5.47 | transport reserved + reuse stream create |
| v2.5.48 | не закрывать shared UDP socket при relay_free |
| v2.5.49 | rekey expiration sync — автоматический re-handshake |
| v2.5.51 | IP/TCP checksum network-order, Linux-like SYN fingerprint |
| v2.5.52 | 16-byte WG padding, static buffer MIPS, Telegram работает |
| v2.5.53 | idle timer + ECONNRESET + awg_stream_send check |
| v2.5.57 | SO_SNDBUF 256KB на client_fd |
| v2.5.58 | backpressure to_client_buf+EPOLLOUT, 531 KB/s (10× рост) |
| v2.5.59 | SYN-ACK timeout 5s, SO_RCVBUF 4MB, log spam fix |
| v2.5.60 | HC двухфазный: WG handshake + inner TCP probe 1.1.1.1:80 |
| v2.5.66 | config list servers (имена с пробелами), consecutive_fail |
| v2.5.67 | AWG idle timeout 300s |
| v2.5.74 | CLOCK_MONOTONIC возраст ключа — защита от NTP clock skew |
| v2.5.75 | удалён retransmit (ломал TCP ordering) |
| v2.5.76 | reorder-буфер (RFC 6479 out-of-order) |
| v2.5.77 | MSS=1240 (было 1360 → фрагментация в MTU 1280 туннеле) |
| v2.5.78-80 | DNS IPv6 listener (корень «тщетно подключается» на iPhone) |
| v2.5.81 | SYN-ACK timeout 15s + RFC 793 SYN-retransmit |
| v2.5.82 | проактивный rekey 120s (WARP RejectAfterTime=180s) |
| v2.5.83 | dual-key бесшовный rekey, 18.5MB сквозь rekey без обрыва |

### Status log (сокращённо)

- **2026-05-30** — v2.5.58–v2.5.83: AWG полностью стабилен. Telegram
  работает, видео 18.5MB сквозь rekey, dual-key бесшовный rekey каждые 120s.
  Корни исправлены: backpressure (531KB/s), MSS=1240, IPv6 DNS listener,
  CLOCK_MONOTONIC key age, reorder-буфер, проактивный+dual-key rekey.
  Открыто: скорость (T1-AWG-throughput Фаза 3+) — следующий этап.
- **2026-04-19** — v1.5.0: audit_v42 0/0/0, IPv6 fake-ip
- **2026-04-21** — v1.5.1: DNS Client Compatibility (PTR, Cookie, DoH/DoT)
- **2026-05-01–03** — v1.5.27–v1.5.67: Reality, gRPC, WS, XHTTP, Hysteria2, SIGHUP
- **2026-05-06–10** — v1.5.79–v1.5.173: Mux.Cool, TUIC v5, AnyTLS, audit_v47+v49
- **2026-05-14** — v2.3.x–v2.4.0: audit_v49+v50, Dashboard tooltip system
- **2026-05-15** — v2.4.1–v2.4.8: CI/CD, LuCI, AND/LB, 77 PASS 0 FAIL
- **2026-05-16** — v2.5.0–v2.5.8: AWG first working, N7 DNS, N8 Flow Offload
- **2026-05-26** — v2.5.58–v2.5.60: AWG throughput 531 KB/s, backpressure, двухфазный HC, Telegram стабильно
- **2026-05-17** — v2.5.9–v2.5.21: audit_v52, VMess, SS2022, ShadowTLS
- **2026-05-22** — v2.5.43: Trojan+Reality закрыт
- **2026-05-23** — v2.5.44–v2.5.46: TAI64N, blake2s sigma fix, AWG handshake ✅
- **2026-05-25** — v2.5.47–v2.5.57: AWG transport, Telegram работает, throughput в работе
