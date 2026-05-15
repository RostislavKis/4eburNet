/*
 * rule_provider_stubs.c
 *
 * Заглушки внешних символов для теста rule_provider.c.
 * log_msg не здесь — приходит из src/log.c (линкуется отдельно).
 * json_escape_str — упрощённый stub вместо net_utils.c (чтобы не тянуть wolfssl).
 */

#include "net_utils.h"
#include "http_server.h"
#include "resource_manager.h"
#include <string.h>

int net_spawn_fetch(const char *url, const char *dest_path)
{
    (void)url; (void)dest_path;
    return -1;
}

int net_spawn_fetch_h(const char *url, const char *dest_path,
                      const char extra_headers[][256], int hdr_cnt)
{
    (void)url; (void)dest_path; (void)extra_headers; (void)hdr_cnt;
    return -1;
}

void http_server_emit_event(const char *json_event)
{
    (void)json_event;
}

DeviceProfile rm_detect_profile(void)
{
    return DEVICE_NORMAL;
}

int json_escape_str(const char *src, char *dst, size_t dst_size)
{
    if (!src || !dst || dst_size < 2) {
        if (dst && dst_size > 0) dst[0] = '\0';
        return 0;
    }
    size_t pos = 0;
    for (; *src && pos + 1 < dst_size; src++)
        dst[pos++] = (char)(unsigned char)*src;
    dst[pos] = '\0';
    return (int)pos;
}
