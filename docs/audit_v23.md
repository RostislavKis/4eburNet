# Devil Audit v23 — финальный аудит перед v1.0.0 (E.4)

**Дата:** 2026-04-11
**Статус:** полный обзор перед тегированием v1.0.0
**Scope:** SDK Makefile, Kconfig, LuCI Makefile, cross-module, build pipeline

---

## 1. SDK core/Makefile

| Проверка | Статус |
|----------|--------|
| PKG_NAME = `4eburnet-core` | 🟢 |
| PKG_VERSION = `1.0.0` | 🟢 |
| DEPENDS = `+libwolfssl +libucode` | 🟢 |
| Install → `$(1)/usr/sbin` | 🟢 |
| EBURNET_CFLAGS: 12 `$(if CONFIG_*,...)` | 🟢 все 12 флагов |
| EBURNET_SOURCES: 39 .c файлов | 🟢 совпадают с Makefile.dev |
| Build/Prepare: `$(CP) ./src/* ... ./include` | 🟢 |
| wolfSSL: `-lwolfssl -lm` | 🟢 (SDK предоставляет libwolfssl) |

**Вердикт: 🟢 корректен.**

---

## 2. Kconfig ↔ Makefile.dev ↔ код

| Флаг | Kconfig | Makefile.dev | Код | Makefile SDK |
|------|---------|-------------|-----|-------------|
| VLESS | ✓ | ✓ (3 профиля) | ✓ | ✓ |
| TROJAN | ✓ | ✓ | ✓ | ✓ |
| SS | ✓ | ✓ | ✓ | ✓ |
| AWG | ✓ | ✓ | ✓ | ✓ |
| STLS | ✓ | ✓ | ✓ | ✓ |
| FAKE_IP | ✓ | ✓ | ✓ | ✓ |
| DOH | ✓ | ✓ | ✓ | ✓ |
| QUIC | ✓ | ✓ | ✓ | ✓ |
| DOQ | ✓ | ✓ | ✓ | ✓ |
| PROXY_PROVIDERS | ✓ | ✓ | ✓ | ✓ |
| SNIFFER | ✓ | ✓ | ✓ | ✓ |
| DPI | ✓ | ✓ | ✓ | ✓ |

**12/12 полное соответствие.** Нет лишних флагов ни в коде, ни в Makefile.

**Вердикт: 🟢 корректен.**

---

## 3. luci-app-4eburnet/Makefile

| Проверка | Статус |
|----------|--------|
| PKG_VERSION = `1.0.0` | 🟢 |
| DEPENDS: `+luci-base +luci-lib-jsonc +ucode-mod-socket +rpcd-mod-rpcsys` | 🟢 |
| Install: rpcd ucode `.uc` | 🟢 |
| Install: rpcd ACL `.json` | 🟢 |
| Install: LuCI menu `.json` | 🟢 |
| Install: 11 JS view файлов (`*.js` wildcard) | 🟢 |
| Install: DPI файлы (ipset, whitelist, autohosts) | 🟢 |
| Install: init.d, hotplug, sub_convert.py | 🟢 |
| Install: legacy luasrc/ (Lua controller) | 🟢 luasrc/ существует |
| PKGARCH = `all` | 🟢 |

**Вердикт: 🟢 корректен.**

---

## 4. Cross-module: ShadowTLS + TLS

| Проверка | Статус |
|----------|--------|
| relay_free: `stls_io` freed | 🟢 строка 588 |
| relay_free: `stls` freed | 🟢 строка 589 |
| relay_alloc: `stls = NULL`, `stls_io = NULL` | 🟢 |
| RELAY_STLS_SHAKE → inner proto start | 🟢 stls_io allocated for vless/trojan |
| tls.c: io_send/io_recv → wolfSSL callbacks | 🟢 else wolfSSL_set_fd |
| relay_transfer: `!r->use_tls` guard для SS path | 🟢 |
| wolfSSL TLS path: через stls_ssl_send/recv callbacks | 🟢 |
| dispatcher_cleanup: `stls_buf` freed | 🟢 |
| dispatcher_init: `stls_buf` allocated | 🟢 |
| stls_ssl_recv: rbuf overflow → ERR_GENERAL | 🟢 |
| default case в switch(r->state) | 🟢 |

**Вердикт: 🟢 корректен.**

---

## 5. Build pipeline

| Проверка | Статус |
|----------|--------|
| `make -f Makefile.dev` компилируется | 🟢 0 warnings (кроме doq.c pedantic) |
| `make -f Makefile.dev test` | 🟢 9× ALL PASS |
| Бинарник | 🟢 1.6MB (лимит 4MB) |
| `bash -n scripts/build.sh` | 🟢 синтаксис OK |
| `python3 -m py_compile tools/sub_convert.py` | 🟢 OK |
| `set -eo pipefail` в build.sh | 🟢 |
| SDK_BASE параметризован | 🟢 |

**Вердикт: 🟢 корректен.**

---

## 6. Тестовое покрытие

| Тест-суит | Тестов | Статус |
|-----------|--------|--------|
| test_hysteria2_uri | 43 | ALL PASS |
| test_hysteria2_udp | 33 | ALL PASS |
| test_hysteria2_cc | 31 | ALL PASS |
| test_dpi_filter | 41 | ALL PASS |
| test_dpi_payload | 19 | ALL PASS |
| test_dpi_strategy | 8 | ALL PASS |
| test_cdn_updater | 30 | ALL PASS |
| test_hmac_sha256 | 13 | ALL PASS |
| test_shadowtls | 21 | ALL PASS |
| **Итого** | **~239** | **ALL PASS** |

---

## 7. Git history

30 коммитов в этой сессии. Блоки C.5-C.6, D.1-D.4, E.1-E.3 + 13 devil audits (v17-v23) + все fixes.

---

## Итог

| Уровень | Количество | Детали |
|---------|-----------|--------|
| 🔴 RED | 0 | — |
| 🟡 YELLOW | 0 | — |
| 🟢 GREEN | 28 | SDK, Kconfig, LuCI, cross-module, build, tests |

**Вердикт: проект готов к v1.0.0.** Ноль критических, ноль жёлтых. Все аудиты v17-v22 закрыты. 239 тестов проходят. Бинарник 1.6MB. SDK Makefile синхронизирован.
