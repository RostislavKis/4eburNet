#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <sys/socket.h>
#include <stddef.h>

/* Форматирование sockaddr_storage в строку "IP:порт" (M-01) */
void net_format_addr(const struct sockaddr_storage *ss,
                     char *buf, size_t buflen);

#endif /* NET_UTILS_H */
