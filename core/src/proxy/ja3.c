/*
 * ja3.c — JA3/JA4 TLS fingerprint вычисление (v1.2-3)
 *
 * JA3:  MD5(ver,ciphers,exts,groups,ecpf) → 32 hex
 * JA4:  t{ver}{sni}{cc}{ec}{alpn}_{SHA256_ciphers12}_{SHA256_ext12}
 */

#include "proxy/ja3.h"
#include "crypto/tiny_md5.h"
#include "4eburnet.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

/* Встроенные эталоны — меняются с версией браузера, только ориентир */
static const Ja3Reference g_references[] = {
    {"Chrome 120",  "cd08e31494f9531f560d64c695473da9", "t13d"},
    {"Firefox 121", "b32309a26951912be7dba376398abc3b", "t13d"},
    {"Safari 17",   "773906b0efdefa24a7f2b8eb6985bf76", "t13d"},
    {"curl 7.x",    "d4e5b18d6b55c71db6a4f89e91c8b8d0", "t13d"},
    {NULL, NULL, NULL},
};

const Ja3Reference *ja3_get_references(void)
{
    return g_references;
}

const char *ja3_match_reference(const char *ja3_hash)
{
    if (!ja3_hash || ja3_hash[0] == '\0') return NULL;
    for (int i = 0; g_references[i].name; i++) {
        if (strcmp(g_references[i].ja3_hash, ja3_hash) == 0)
            return g_references[i].name;
    }
    return NULL;
}

/* append_u16_list — добавить uint16_t массив через '-' */
static void append_u16_list(char *buf, size_t bufsz, size_t *pos,
                             const uint16_t *arr, int cnt)
{
    for (int i = 0; i < cnt; i++) {
        if (*pos >= bufsz) return;
        int w = snprintf(buf + *pos, bufsz - *pos,
                         i ? "-%u" : "%u", (unsigned)arr[i]);
        if (w > 0 && *pos + (size_t)w < bufsz) *pos += (size_t)w;
    }
}

int ja3_compute(const ClientHelloInfo *info,
                char ja3_out[33],
                char *ja3_str_out, size_t ja3_str_size)
{
    /* static: MIPS safe — однопоточный epoll, ~640 байт не на стеке */
    static char str[640];
    size_t pos = 0;

    int w = snprintf(str, sizeof(str), "%u,", (unsigned)info->tls_version);
    if (w > 0) pos = (size_t)w;

    append_u16_list(str, sizeof(str), &pos, info->ciphers, info->cipher_count);
    if (pos < sizeof(str) - 1) str[pos++] = ',';
    append_u16_list(str, sizeof(str), &pos, info->extensions, info->ext_count);
    if (pos < sizeof(str) - 1) str[pos++] = ',';
    append_u16_list(str, sizeof(str), &pos, info->groups, info->group_count);
    if (pos < sizeof(str) - 1) str[pos++] = ',';

    for (int i = 0; i < info->ecpf_count; i++) {
        if (pos >= sizeof(str)) break;
        int ew = snprintf(str + pos, sizeof(str) - pos,
                          i ? "-%u" : "%u", (unsigned)info->ecpf[i]);
        if (ew > 0 && pos + (size_t)ew < sizeof(str)) pos += (size_t)ew;
    }
    str[pos] = '\0';

    tiny_md5_hex(str, ja3_out);

    if (ja3_str_out && ja3_str_size > 0) {
        strncpy(ja3_str_out, str, ja3_str_size - 1);
        ja3_str_out[ja3_str_size - 1] = '\0';
    }
    return 0;
}

static int cmp_u16(const void *a, const void *b)
{
    return (int)(*(const uint16_t *)a) - (int)(*(const uint16_t *)b);
}

static const char *tls_ver_str(uint16_t v)
{
    switch (v) {
    case 0x0304: return "13";
    case 0x0303: return "12";
    case 0x0302: return "11";
    case 0x0301: return "10";
    default:     return "00";
    }
}

int ja4_compute(const ClientHelloInfo *info, char ja4_out[40])
{
    uint16_t ver = info->supported_version ? info->supported_version
                                           : info->tls_version;
    /* static: MIPS safe */
    static char cipher_str[320];
    static char ext_str[160];

    /* Отсортированные ciphers → hex строка */
    uint16_t sorted[JA3_CIPHER_MAX];
    int cc = info->cipher_count;
    memcpy(sorted, info->ciphers, (size_t)cc * sizeof(uint16_t));
    qsort(sorted, (size_t)cc, sizeof(uint16_t), cmp_u16);

    size_t cpos = 0;
    for (int i = 0; i < cc; i++) {
        if (cpos >= sizeof(cipher_str)) break;
        int cw = snprintf(cipher_str + cpos, sizeof(cipher_str) - cpos,
                          i ? ",%04x" : "%04x", (unsigned)sorted[i]);
        if (cw > 0 && cpos + (size_t)cw < sizeof(cipher_str)) cpos += (size_t)cw;
    }
    cipher_str[cpos] = '\0';

    /* Extensions без SNI(0x0000) и ALPN(0x0010) */
    size_t epos = 0;
    bool first = true;
    for (int i = 0; i < info->ext_count; i++) {
        uint16_t et = info->extensions[i];
        if (et == 0x0000 || et == 0x0010) continue;
        if (epos >= sizeof(ext_str)) break;
        int ew = snprintf(ext_str + epos, sizeof(ext_str) - epos,
                          first ? "%04x" : ",%04x", (unsigned)et);
        if (ew > 0 && epos + (size_t)ew < sizeof(ext_str)) epos += (size_t)ew;
        first = false;
    }
    ext_str[epos] = '\0';

    /* SHA-256 → первые 12 hex символов
     * static: wc_InitSha256 реинициализирует перед каждым вызовом */
    static wc_Sha256 sha;
    static byte digest[WC_SHA256_DIGEST_SIZE];
    char cipher12[13], ext12[13];

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (const byte *)cipher_str, (word32)cpos);
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);
    for (int i = 0; i < 6; i++)
        snprintf(cipher12 + i*2, 3, "%02x", (unsigned)digest[i]);
    cipher12[12] = '\0';

    wc_InitSha256(&sha);
    wc_Sha256Update(&sha, (const byte *)ext_str, (word32)epos);
    wc_Sha256Final(&sha, digest);
    wc_Sha256Free(&sha);
    for (int i = 0; i < 6; i++)
        snprintf(ext12 + i*2, 3, "%02x", (unsigned)digest[i]);
    ext12[12] = '\0';

    /* ALPN: первые 2 символа первого протокола, или "00" */
    char alpn2[3] = "00";
    if (info->alpn_found && info->alpn[0]) {
        alpn2[0] = info->alpn[0];
        alpn2[1] = info->alpn[1] ? info->alpn[1] : '0';
        alpn2[2] = '\0';
    }

    /* промежуточный буфер: GCC не знает длину tls_ver_str (всегда 2 символа) */
    char buf[48];
    int n = snprintf(buf, sizeof(buf), "t%s%c%02d%02d%s_%s_%s",
                     tls_ver_str(ver),
                     info->sni_found ? 'd' : 'i',
                     cc > 99 ? 99 : cc,
                     info->ext_count > 99 ? 99 : info->ext_count,
                     alpn2, cipher12, ext12);
    if (n > 0) { memcpy(ja4_out, buf, (size_t)n < 39 ? (size_t)n + 1 : 39); ja4_out[39] = '\0'; }
    return 0;
}
