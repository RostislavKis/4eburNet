#ifndef NTP_BOOTSTRAP_H
#define NTP_BOOTSTRAP_H

#include <stdbool.h>

/* Минимальное валидное время: 2020-01-01 00:00:00 UTC */
#define NTP_MIN_VALID_TIME  1577836800LL

/* Таймаут подключения к одному хосту (секунды) */
#define NTP_CONNECT_TIMEOUT 3

/*
 * Проверка и установка времени через HTTP Date: заголовок.
 * Используется при холодном старте роутера (время = 1970),
 * когда TLS сертификаты невалидны.
 *
 * Возвращает 0 при успехе или если время уже корректно.
 * Возвращает -1 если все попытки провалились.
 */
int  ntp_bootstrap(void);

/* Проверка: системное время >= 2020-01-01 */
bool ntp_time_is_valid(void);

#endif /* NTP_BOOTSTRAP_H */
