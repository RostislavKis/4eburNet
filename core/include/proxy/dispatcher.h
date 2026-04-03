#ifndef DISPATCHER_H
#define DISPATCHER_H

#include "proxy/tproxy.h"

#include <stdint.h>
#include <stddef.h>

/* Обработать новое TCP соединение от TPROXY */
void dispatcher_handle_conn(tproxy_conn_t *conn);

/* Обработать UDP дейтаграмму от TPROXY */
void dispatcher_handle_udp(tproxy_conn_t *conn,
                           const uint8_t *data, size_t len);

#endif /* DISPATCHER_H */
