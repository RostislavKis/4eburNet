#ifndef PHOENIX_H
#define PHOENIX_H

#define PHOENIX_VERSION "0.1.0"
#define PHOENIX_NAME    "phoenix-router"

/* Профили устройств — выбираются автоматически по объёму RAM */
typedef enum {
    DEVICE_MICRO,   /* до 64 МБ: минимальный набор, без кеша DNS */
    DEVICE_NORMAL,  /* 128-256 МБ: стандартный режим */
    DEVICE_FULL     /* 512+ МБ: все возможности, расширенный кеш */
} DeviceProfile;

/* Лимиты для каждого профиля */
#define MICRO_MAX_CONNECTIONS   64
#define MICRO_MAX_RULES         256
#define MICRO_DNS_CACHE_SIZE    0

#define NORMAL_MAX_CONNECTIONS  512
#define NORMAL_MAX_RULES        2048
#define NORMAL_DNS_CACHE_SIZE   4096

#define FULL_MAX_CONNECTIONS    4096
#define FULL_MAX_RULES          16384
#define FULL_DNS_CACHE_SIZE     32768

/* Пути по умолчанию */
#define PHOENIX_CONFIG_PATH     "/etc/config/phoenix"
#define PHOENIX_PID_FILE        "/var/run/phoenix.pid"
#define PHOENIX_LOG_FILE        "/var/log/phoenix.log"
#define PHOENIX_RULES_DIR       "/etc/phoenix/rules/"

#endif /* PHOENIX_H */
