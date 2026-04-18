#ifndef DNS_UPSTREAM_H
#define DNS_UPSTREAM_H

#include "config.h"
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

/* Обычный UDP DNS запрос к upstream */
ssize_t dns_upstream_query(const char *server_ip, uint16_t server_port,
                           const uint8_t *query, size_t query_len,
                           uint8_t *response, size_t resp_buflen,
                           int timeout_ms);

/* DoH запрос (RFC 8484) через wolfSSL TLS */
ssize_t dns_doh_query(const DnsConfig *cfg,
                      const uint8_t *query, size_t query_len,
                      uint8_t *response, size_t resp_buflen);

/* DoT запрос (RFC 7858) через wolfSSL TLS */
ssize_t dns_dot_query(const char *server_ip, uint16_t server_port,
                      const char *sni,
                      const uint8_t *query, size_t query_len,
                      uint8_t *response, size_t resp_buflen);

#endif /* DNS_UPSTREAM_H */
