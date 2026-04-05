/*
 * Минимальный DNS парсер/builder
 */

#include "dns/dns_packet.h"
#include <string.h>
#include <ctype.h>

void dns_normalize_qname(char *qname)
{
    for (char *p = qname; *p; p++)
        *p = tolower((unsigned char)*p);
    size_t len = strlen(qname);
    if (len > 0 && qname[len - 1] == '.')
        qname[len - 1] = '\0';
}

int dns_parse_query(const uint8_t *pkt, size_t len, dns_query_t *q)
{
    if (len < 12)
        return -1;

    memset(q, 0, sizeof(*q));

    q->id    = ((uint16_t)pkt[0] << 8) | pkt[1];
    q->is_query = !(pkt[2] & 0x80);
    q->opcode   = (pkt[2] >> 3) & 0x0F;
    q->rd       = !!(pkt[2] & 0x01);

    uint16_t qdcount = ((uint16_t)pkt[4] << 8) | pkt[5];
    if (qdcount == 0)
        return -1;

    /* Парсинг QNAME (label format) */
    size_t pos = 12;
    size_t qname_pos = 0;

    while (pos < len) {
        uint8_t label_len = pkt[pos++];
        if (label_len == 0)
            break;
        if (label_len > 63 || pos + label_len > len)
            return -1;
        if (qname_pos > 0 && qname_pos < sizeof(q->qname) - 1)
            q->qname[qname_pos++] = '.';
        for (uint8_t i = 0; i < label_len && qname_pos < sizeof(q->qname) - 1; i++)
            q->qname[qname_pos++] = pkt[pos++];
    }
    q->qname[qname_pos] = '\0';
    dns_normalize_qname(q->qname);

    if (pos + 4 > len)
        return -1;
    q->qtype  = ((uint16_t)pkt[pos] << 8) | pkt[pos + 1];
    q->qclass = ((uint16_t)pkt[pos + 2] << 8) | pkt[pos + 3];

    return 0;
}

int dns_build_nxdomain(const dns_query_t *q, uint8_t *buf, size_t buflen)
{
    if (buflen < 12)
        return -1;

    /* Копируем заголовок: QR=1, RCODE=3 (NXDOMAIN) */
    buf[0] = (q->id >> 8) & 0xFF;
    buf[1] = q->id & 0xFF;
    buf[2] = 0x81;  /* QR=1, RD=1 */
    buf[3] = 0x83;  /* RA=1, RCODE=3 */
    buf[4] = 0; buf[5] = 1;  /* QDCOUNT=1 */
    buf[6] = 0; buf[7] = 0;  /* ANCOUNT=0 */
    buf[8] = 0; buf[9] = 0;  /* NSCOUNT=0 */
    buf[10] = 0; buf[11] = 0; /* ARCOUNT=0 */

    /* Копируем вопрос обратно (QNAME + QTYPE + QCLASS) */
    size_t pos = 12;
    const char *name = q->qname;
    while (*name) {
        const char *dot = strchr(name, '.');
        size_t label_len = dot ? (size_t)(dot - name) : strlen(name);
        if (pos + 1 + label_len >= buflen) return -1;
        buf[pos++] = (uint8_t)label_len;
        memcpy(buf + pos, name, label_len);
        pos += label_len;
        name += label_len + (dot ? 1 : 0);
    }
    if (pos >= buflen) return -1;
    buf[pos++] = 0;  /* root label */

    if (pos + 4 > buflen) return -1;
    buf[pos++] = (q->qtype >> 8) & 0xFF;
    buf[pos++] = q->qtype & 0xFF;
    buf[pos++] = (q->qclass >> 8) & 0xFF;
    buf[pos++] = q->qclass & 0xFF;

    return (int)pos;
}

int dns_build_forward_reply(const dns_query_t *q,
                            const uint8_t *upstream_reply, size_t reply_len,
                            uint8_t *buf, size_t buflen)
{
    if (reply_len < 2 || reply_len > buflen)
        return -1;
    memcpy(buf, upstream_reply, reply_len);
    /* Подставляем ID клиента */
    buf[0] = (q->id >> 8) & 0xFF;
    buf[1] = q->id & 0xFF;
    return (int)reply_len;
}

uint32_t dns_extract_min_ttl(const uint8_t *reply, size_t len)
{
    if (len < 12) return 60;

    uint16_t ancount = ((uint16_t)reply[6] << 8) | reply[7];
    if (ancount == 0) return 60;

    /* Пропустить вопросы */
    uint16_t qdcount = ((uint16_t)reply[4] << 8) | reply[5];
    size_t pos = 12;
    for (uint16_t i = 0; i < qdcount && pos < len; i++) {
        while (pos < len && reply[pos] != 0) {
            if ((reply[pos] & 0xC0) == 0xC0) { pos += 2; goto skip_done; }
            uint8_t label_len = reply[pos];
            if (pos + 1 + label_len > len) return 60;  /* защита от OOB */
            pos += 1 + label_len;
        }
        if (pos < len) pos++;  /* root label */
        skip_done:
        pos += 4; /* QTYPE + QCLASS */
    }

    /* Парсить ответы для TTL */
    uint32_t min_ttl = 86400;
    for (uint16_t i = 0; i < ancount && pos + 10 < len; i++) {
        /* Пропустить NAME */
        if (pos >= len) break;
        if ((reply[pos] & 0xC0) == 0xC0) {
            pos += 2;
        } else {
            while (pos < len && reply[pos]) {
                uint8_t label_len = reply[pos];
                if (pos + 1 + label_len > len) return 60;
                pos += 1 + label_len;
            }
            if (pos < len) pos++;
        }
        /* TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) */
        if (pos + 10 > len) break;
        uint32_t ttl = ((uint32_t)reply[pos+4] << 24) |
                       ((uint32_t)reply[pos+5] << 16) |
                       ((uint32_t)reply[pos+6] << 8) |
                       reply[pos+7];
        if (ttl < min_ttl) min_ttl = ttl;
        uint16_t rdlength = ((uint16_t)reply[pos+8] << 8) | reply[pos+9];
        pos += 10 + rdlength;
    }
    return min_ttl > 0 ? min_ttl : 60;
}
