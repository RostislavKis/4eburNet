/*
 * sniffer.c — TLS ClientHello парсер (3.6 / v1.2-3)
 *
 * sniffer_parse_hello(): полный парсер ClientHello для JA3/JA4.
 * sniffer_peek_sni(): обёртка для обратной совместимости.
 */

#include "proxy/sniffer.h"
#include "4eburnet.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

#define SNIFFER_PEEK_SIZE  512

int sniffer_parse_hello(int fd, ClientHelloInfo *out)
{
    uint8_t buf[SNIFFER_PEEK_SIZE];
    ssize_t n = recv(fd, buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
    if (n < 5) return -1;

    if (buf[0] != 0x16) return -1;
    if (buf[1] != 0x03 || buf[2] < 0x01 || buf[2] > 0x04) return -1;

    uint16_t rec_len = ((uint16_t)buf[3] << 8) | buf[4];
    if (rec_len < 4)   return -1;
    if ((size_t)n < 9) return -1;

    if (buf[5] != 0x01) return -1;

    uint32_t hs_len = ((uint32_t)buf[6] << 16) |
                      ((uint32_t)buf[7] << 8)   |
                      (uint32_t)buf[8];
    if (hs_len < 34) return -1;

    /* legacy_version из ClientHello body — используется в JA3 */
    size_t pos = 9;
    if ((size_t)n < pos + 2) return -1;
    out->tls_version = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2 + 32;  /* version + random */
    if ((size_t)n < pos + 1) return -1;

    uint8_t sid_len = buf[pos++];
    if (sid_len > 32) return -1;
    pos += sid_len;

    /* cipher_suites: сохраняем список без GREASE */
    if ((size_t)n < pos + 2) return -1;
    uint16_t cs_len = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;
    for (size_t i = 0; i + 1 < (size_t)cs_len && pos + i + 1 < (size_t)n;
         i += 2) {
        uint16_t cs = ((uint16_t)buf[pos + i] << 8) | buf[pos + i + 1];
        if (!ja3_is_grease(cs) && out->cipher_count < JA3_CIPHER_MAX)
            out->ciphers[out->cipher_count++] = cs;
    }
    pos += cs_len;

    if ((size_t)n < pos + 1) return -1;
    uint8_t cm_len = buf[pos++];
    pos += cm_len;

    if ((size_t)n < pos + 2) return -1;
    uint16_t ext_total = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
    pos += 2;

    size_t ext_end = pos + ext_total;
    if (ext_end > (size_t)n) ext_end = (size_t)n;

    while (pos + 4 <= ext_end) {
        uint16_t ext_type = ((uint16_t)buf[pos]     << 8) | buf[pos + 1];
        uint16_t ext_len  = ((uint16_t)buf[pos + 2] << 8) | buf[pos + 3];
        pos += 4;
        if (pos + ext_len > ext_end) break;

        /* Тип extension записываем без GREASE */
        if (!ja3_is_grease(ext_type) && out->ext_count < JA3_EXT_MAX)
            out->extensions[out->ext_count++] = ext_type;

        if (ext_type == 0x0000 && ext_len >= 5) {
            /* SNI (RFC 6066): list_len(2) + name_type(1) + name_len(2) + name */
            if (buf[pos + 2] != 0x00) { pos += ext_len; continue; }
            uint16_t name_len = ((uint16_t)buf[pos + 3] << 8) | buf[pos + 4];
            if (name_len == 0 || pos + 5 + name_len > ext_end)
                { pos += ext_len; continue; }
            size_t copy_len = name_len;
            if (copy_len >= sizeof(out->sni)) copy_len = sizeof(out->sni) - 1;
            memcpy(out->sni, buf + pos + 5, copy_len);
            out->sni[copy_len] = '\0';
            /* null-байт в SNI невалиден (RFC 6066) */
            if (strlen(out->sni) != copy_len) {
                log_msg(LOG_DEBUG, "SNI sniffer: null-байт в SNI — отклонено");
                out->sni[0] = '\0';
            } else {
                out->sni_found = true;
            }
        } else if (ext_type == 0x000a && ext_len >= 2) {
            /* supported_groups: list_len(2) + groups[] */
            uint16_t gl = ((uint16_t)buf[pos] << 8) | buf[pos + 1];
            for (size_t i = 2; i + 1 < (size_t)gl + 2 && i + 1 < ext_len
                               && pos + i + 1 < ext_end; i += 2) {
                uint16_t g = ((uint16_t)buf[pos + i] << 8) | buf[pos + i + 1];
                if (!ja3_is_grease(g) && out->group_count < JA3_GROUP_MAX)
                    out->groups[out->group_count++] = g;
            }
        } else if (ext_type == 0x000b && ext_len >= 1) {
            /* ec_point_formats: count(1) + formats[] */
            uint8_t fc = buf[pos];
            for (uint8_t i = 0; i < fc && (size_t)(1 + i) < ext_len
                                && out->ecpf_count < JA3_ECPF_MAX; i++)
                out->ecpf[out->ecpf_count++] = buf[pos + 1 + i];
        } else if (ext_type == 0x0010 && ext_len >= 4) {
            /* ALPN (RFC 7301): list_len(2) + proto_len(1) + proto */
            uint8_t plen = buf[pos + 2];
            if (plen > 0 && plen <= 31 && pos + 3 + plen <= ext_end) {
                memcpy(out->alpn, buf + pos + 3, plen);
                out->alpn[plen] = '\0';
                out->alpn_found = true;
            }
        } else if (ext_type == 0x002b && ext_len >= 3) {
            /* supported_versions (TLS 1.3): list_len(1) + versions[] */
            uint8_t vl   = buf[pos];
            uint8_t vlim = (vl < ext_len - 1) ? vl : (uint8_t)(ext_len - 1);
            for (uint8_t i = 0; i + 1 < vlim; i += 2) {
                uint16_t v = ((uint16_t)buf[pos + 1 + i] << 8)
                             | buf[pos + 2 + i];
                if (!ja3_is_grease(v) && v > out->supported_version)
                    out->supported_version = v;
            }
        } else if (ext_type == 0xfe0d || ext_type == 0xffce) {
            /* ECH (RFC 9180) или ESNI legacy draft.
             * Payload не парсим — достаточно факта наличия.
             * При ECH inner ClientHello зашифрован → SNI недоступен. */
            out->ech_found    = true;
            out->ech_ext_type = ext_type;
        }
        pos += ext_len;
    }

    return 0;
}

int sniffer_peek_sni(int fd, char *sni_buf, size_t sni_buflen)
{
    if (sni_buf && sni_buflen > 0) sni_buf[0] = '\0';
    if (!sni_buf || sni_buflen < 2) return 0;

    ClientHelloInfo *info = calloc(1, sizeof(ClientHelloInfo));
    if (!info) return 0;

    int ret = 0;
    if (sniffer_parse_hello(fd, info) == 0 && info->sni_found) {
        size_t l = strlen(info->sni);
        if (l >= sni_buflen) l = sni_buflen - 1;
        memcpy(sni_buf, info->sni, l);
        sni_buf[l] = '\0';
        ret = (int)l;
    }
    free(info);
    return ret;
}
