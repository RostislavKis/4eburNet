#ifndef PHOENIX_H
#define PHOENIX_H

#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#define PHOENIX_VERSION "0.1.0"
#define PHOENIX_NAME    "phoenixd"

/* Профили устройств — выбираются автоматически по объёму RAM */
typedef enum {
    DEVICE_MICRO,   /* до 64 МБ: минимальный набор, без QUIC */
    DEVICE_NORMAL,  /* 64-128 МБ: все протоколы */
    DEVICE_FULL     /* 128+ МБ: все возможности, статистика */
} DeviceProfile;

/* Лимиты для каждого профиля (согласно CLAUDE.md) */
#define MICRO_MAX_CONNECTIONS   256
#define MICRO_BUFFER_SIZE       4096
#define MICRO_MAX_RULES         256
#define MICRO_DNS_CACHE_SIZE    0

#define NORMAL_MAX_CONNECTIONS  2048
#define NORMAL_BUFFER_SIZE      16384
#define NORMAL_MAX_RULES        2048
#define NORMAL_DNS_CACHE_SIZE   4096

#define FULL_MAX_CONNECTIONS    16384
#define FULL_BUFFER_SIZE        65536
#define FULL_MAX_RULES          16384
#define FULL_DNS_CACHE_SIZE     32768

/* Пути по умолчанию */
#define PHOENIX_CONFIG_PATH     "/etc/config/phoenix"
#define PHOENIX_PID_FILE        "/var/run/phoenix.pid"
#define PHOENIX_LOG_FILE        "/tmp/phoenix.log"
#define PHOENIX_LOG_MAX_BYTES   (512 * 1024)  /* 512KB — защита tmpfs */
#define PHOENIX_RULES_DIR       "/etc/phoenix/rules/"

/* Версия протокола IPC между phoenixd и LuCI */
#define PHOENIX_IPC_VERSION     1
#define PHOENIX_IPC_SOCKET      "/var/run/phoenix.sock"

/* Коды команд IPC */
typedef enum {
    IPC_CMD_STATUS    = 1,  /* запрос статуса демона */
    IPC_CMD_RELOAD    = 2,  /* перечитать конфиг */
    IPC_CMD_STOP      = 3,  /* остановить демон */
    IPC_CMD_STATS     = 4,  /* запрос статистики */
} ipc_command_t;

/* Коды ответов IPC */
typedef enum {
    IPC_OK            = 0,
    IPC_ERR_UNKNOWN   = 1,
    IPC_ERR_BUSY      = 2,
    IPC_ERR_CONFIG    = 3,
} ipc_status_t;

/* Заголовок IPC сообщения (фиксированный размер) */
typedef struct {
    uint8_t  version;     /* PHOENIX_IPC_VERSION */
    uint8_t  command;     /* ipc_command_t */
    uint16_t length;      /* длина payload после заголовка */
    uint32_t request_id;  /* для сопоставления ответов */
} __attribute__((packed)) ipc_header_t;

/* Уровни логирования */
typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO  = 1,
    LOG_WARN  = 2,
    LOG_ERROR = 3,
} log_level_t;

/* Предварительные объявления */
struct PhoenixConfig;

/* Глобальное состояние демона */
typedef struct {
    DeviceProfile        profile;
    struct PhoenixConfig *config;
    volatile sig_atomic_t running;      /* флаг главного цикла */
    volatile sig_atomic_t reload;      /* флаг перечитки конфига */
    int                  ipc_fd;
    time_t               start_time;
    uint64_t             connections_total;
} PhoenixState;

/* Логирование */
void log_init(const char *path, log_level_t min_level);
void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void log_flush(void);
void log_close(void);
void log_set_daemon_mode(bool daemon);

#endif /* PHOENIX_H */
