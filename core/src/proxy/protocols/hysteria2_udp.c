/*
 * Hysteria2 UDP datagrams — encode/decode + fragmentation + session manager
 * Wire format: см. hysteria2_udp.h
 *
 * НЕТ varint 0x403 prefix — датаграммы идут как QUIC unreliable datagrams.
 * НЕТ data_len поля — длина данных = остаток датаграммы.
 */

#ifdef CONFIG_EBURNET_QUIC

#include "proxy/hysteria2_udp.h"
#include "4eburnet.h"

#include <string.h>
#include <stdio.h>

/* ── Вспомогательные read/write big-endian ───────────────────────────── */

static void write_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8); p[3] = (uint8_t)(v & 0xFF);
}

static void write_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)(v & 0xFF);
}

static uint32_t read_u32_be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16)
         | ((uint32_t)p[2] <<  8) |  (uint32_t)p[3];
}

static uint16_t read_u16_be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* ── Encode ──────────────────────────────────────────────────────────── */

int hy2_udp_msg_encode(uint8_t *buf, size_t buf_size,
                       uint32_t session_id, uint16_t packet_id,
                       uint8_t frag_id, uint8_t frag_count,
                       const char *host, uint16_t port,
                       const uint8_t *data, size_t data_len)
{
    if (!buf) return -1;
    if (!data && data_len > 0) return -1;
    if (frag_count == 0) return -1;  /* frag_count всегда >= 1 */

    uint8_t *p   = buf;
    uint8_t *end = buf + buf_size;

#define NEED(n) do { if ((size_t)(end - p) < (size_t)(n)) return -1; } while(0)

    /* Fixed header: SessionID(4) + PacketID(2) + FragID(1) + FragCount(1) = 8 байт */
    NEED(8);
    write_u32_be(p, session_id); p += 4;
    write_u16_be(p, packet_id);  p += 2;
    *p++ = frag_id;
    *p++ = frag_count;

    /* Addr: только для первого фрагмента (frag_id == 0) */
    if (frag_id == 0) {
        if (!host) return -1;
        size_t host_len = strlen(host);
        if (host_len == 0 || host_len > 253) return -1;
        NEED(2 + host_len + 2);
        write_u16_be(p, (uint16_t)host_len); p += 2;
        memcpy(p, host, host_len);           p += host_len;
        write_u16_be(p, port);               p += 2;
    }

    /* Data — до конца датаграммы */
    if (data_len > 0) {
        NEED(data_len);
        memcpy(p, data, data_len);
        p += data_len;
    }

#undef NEED
    return (int)(p - buf);
}

/* ── Decode ──────────────────────────────────────────────────────────── */

int hy2_udp_msg_decode(const uint8_t *buf, size_t buf_size,
                       hy2_udp_msg_t *msg_out,
                       uint8_t *data_out, size_t data_out_size)
{
    if (!buf || !msg_out) return -1;
    if (buf_size < HY2_UDP_HDR_MIN) return -1;

    const uint8_t *p   = buf;
    const uint8_t *end = buf + buf_size;

    msg_out->session_id = read_u32_be(p); p += 4;
    msg_out->packet_id  = read_u16_be(p); p += 2;
    msg_out->frag_id    = *p++;
    msg_out->frag_count = *p++;

    /* frag_count == 0 — некорректный пакет */
    if (msg_out->frag_count == 0) return -1;
    /* frag_id >= frag_count — некорректный */
    if (msg_out->frag_id >= msg_out->frag_count) return -1;

    /* Addr: только у frag_id == 0 */
    msg_out->host[0] = '\0';
    msg_out->port    = 0;

    if (msg_out->frag_id == 0) {
        /* Нужен минимум uint16 HostLen */
        if (end - p < 2) return -1;
        uint16_t host_len = read_u16_be(p); p += 2;
        if (host_len == 0 || host_len > 253) return -1;
        /* HostLen байт + uint16 Port */
        if ((size_t)(end - p) < (size_t)host_len + 2u) return -1;
        memcpy(msg_out->host, p, host_len);
        msg_out->host[host_len] = '\0';
        p += host_len;
        msg_out->port = read_u16_be(p); p += 2;
    }

    /* Data = остаток датаграммы (zero-copy) */
    msg_out->data     = p;
    msg_out->data_len = (size_t)(end - p);

    /* Опциональное копирование payload в caller'ский буфер */
    if (data_out && data_out_size > 0 && msg_out->data_len > 0) {
        size_t copy = (msg_out->data_len < data_out_size)
                    ? msg_out->data_len : data_out_size;
        memcpy(data_out, msg_out->data, copy);
    }

    return (int)buf_size;  /* потреблена вся датаграмма */
}

/* ── Фрагментация ────────────────────────────────────────────────────── */

int hy2_udp_fragment(uint32_t session_id, uint16_t packet_id,
                     const char *host, uint16_t port,
                     const uint8_t *data, size_t data_len,
                     hy2_udp_fragment_t *frags,
                     uint8_t (*frag_bufs)[HY2_UDP_FRAG_SIZE],
                     int max_frags)
{
    if (!frags || !frag_bufs || max_frags <= 0) return -1;
    if (!host || !data) return -1;

    /* Вычислить число фрагментов */
    int count;
    if (data_len == 0) {
        count = 1;
    } else {
        count = (int)((data_len + HY2_UDP_FRAG_PAYLOAD - 1)
                      / HY2_UDP_FRAG_PAYLOAD);
    }
    if (count > max_frags) return -1;
    if (count > 255)       return -1;  /* frag_count: uint8 */

    size_t offset = 0;
    for (int i = 0; i < count; i++) {
        size_t chunk = data_len - offset;
        if (chunk > HY2_UDP_FRAG_PAYLOAD) chunk = HY2_UDP_FRAG_PAYLOAD;

        /* addr передаётся только у первого фрагмента; у прочих encode пропускает */
        int n = hy2_udp_msg_encode(
            frag_bufs[i], HY2_UDP_FRAG_SIZE,
            session_id, packet_id,
            (uint8_t)i, (uint8_t)count,
            (i == 0) ? host : NULL,  /* NULL → addr блок пропускается (frag_id>0) */
            (i == 0) ? port : 0,
            data + offset, chunk);

        if (n < 0) return -1;

        frags[i].buf        = frag_bufs[i];
        frags[i].buf_len    = (size_t)n;
        frags[i].frag_id    = (uint8_t)i;
        frags[i].frag_count = (uint8_t)count;

        offset += chunk;
    }

    return count;
}

/* ── Session manager ─────────────────────────────────────────────────── */

void hy2_udp_session_mgr_init(hy2_udp_session_mgr_t *mgr)
{
    if (mgr) memset(mgr, 0, sizeof(*mgr));
}

int hy2_udp_session_add(hy2_udp_session_mgr_t *mgr,
                        uint32_t session_id,
                        const char *host, uint16_t port)
{
    if (!mgr || !host) return -1;

    /* Найти существующий слот → обновить */
    for (int i = 0; i < HY2_UDP_MAX_SESSIONS; i++) {
        if (mgr->sessions[i].active &&
            mgr->sessions[i].session_id == session_id) {
            snprintf(mgr->sessions[i].host,
                     sizeof(mgr->sessions[i].host), "%s", host);
            mgr->sessions[i].port = port;
            return 0;
        }
    }

    /* Найти свободный слот */
    for (int i = 0; i < HY2_UDP_MAX_SESSIONS; i++) {
        if (!mgr->sessions[i].active) {
            mgr->sessions[i].session_id = session_id;
            snprintf(mgr->sessions[i].host,
                     sizeof(mgr->sessions[i].host), "%s", host);
            mgr->sessions[i].port   = port;
            mgr->sessions[i].active = true;
            return 0;
        }
    }

    log_msg(LOG_WARN,
            "hy2_udp_session_add: таблица заполнена (%d слотов)",
            HY2_UDP_MAX_SESSIONS);
    return -1;
}

hy2_udp_session_t *hy2_udp_session_find(hy2_udp_session_mgr_t *mgr,
                                         uint32_t session_id)
{
    if (!mgr) return NULL;
    for (int i = 0; i < HY2_UDP_MAX_SESSIONS; i++) {
        if (mgr->sessions[i].active &&
            mgr->sessions[i].session_id == session_id)
            return &mgr->sessions[i];
    }
    return NULL;
}

void hy2_udp_session_remove(hy2_udp_session_mgr_t *mgr,
                             uint32_t session_id)
{
    if (!mgr) return;
    for (int i = 0; i < HY2_UDP_MAX_SESSIONS; i++) {
        if (mgr->sessions[i].active &&
            mgr->sessions[i].session_id == session_id) {
            memset(&mgr->sessions[i], 0, sizeof(mgr->sessions[i]));
            return;
        }
    }
}

void hy2_udp_session_mgr_free(hy2_udp_session_mgr_t *mgr)
{
    if (mgr) memset(mgr, 0, sizeof(*mgr));
}

#endif /* CONFIG_EBURNET_QUIC */
