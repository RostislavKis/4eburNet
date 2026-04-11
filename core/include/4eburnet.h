#ifndef EBURNET_H
#define EBURNET_H

#include "4eburnet_config.h"
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>

#define EBURNET_VERSION "1.0.0"
#define EBURNET_NAME    "4eburnetd"

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
#define EBURNET_CONFIG_PATH     "/etc/config/4eburnet"
#define EBURNET_PID_FILE        "/var/run/4eburnet.pid"
#define EBURNET_LOG_FILE        "/tmp/4eburnet.log"
#define EBURNET_LOG_MAX_BYTES   (512 * 1024)  /* 512KB — защита tmpfs (1.5% от 32MB tmpfs на 64MB RAM) */
#define EBURNET_RULES_DIR       "/etc/4eburnet/rules/"

/*/* Версия протокола IPC между 4eburnetd и LuCI */
#define EBURNET_IPC_VERSION     1
#define EBURNET_IPC_SOCKET      "/var/run/4eburnet.sock"

/* Коды команд IPC */
typedef enum {
    IPC_CMD_STATUS          = 1,  /* запрос статуса демона */
    IPC_CMD_RELOAD          = 2,  /* перечитать конфиг */
    IPC_CMD_STOP            = 3,  /* остановить демон */
    IPC_CMD_STATS           = 4,  /* запрос статистики */
    IPC_CMD_GROUP_LIST      = 20, /* список proxy groups */
    IPC_CMD_GROUP_SELECT    = 21, /* ручной выбор сервера в group */
    IPC_CMD_GROUP_TEST      = 22, /* запустить health-check группы */
    IPC_CMD_PROVIDER_LIST   = 23, /* список rule providers */
    IPC_CMD_PROVIDER_UPDATE = 24, /* принудительное обновление provider */
    IPC_CMD_RULES_LIST      = 25, /* список traffic rules */
    IPC_CMD_GEO_STATUS      = 26, /* статус geo менеджера */
    IPC_CMD_CDN_UPDATE      = 30, /* принудительное обновление CDN IP */
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
    uint8_t  version;     /* EBURNET_IPC_VERSION */
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
struct EburNetConfig;

/* Глобальное состояние демона */
typedef struct {
    DeviceProfile        profile;
    struct EburNetConfig *config;
    volatile sig_atomic_t running;      /* флаг главного цикла */
    volatile sig_atomic_t reload;      /* флаг перечитки конфига */
    volatile sig_atomic_t cdn_update_requested; /* запрос обновления CDN IP (C.6) */
    int                  cdn_pipe_fd;    /* read-end pipe от async CDN update, -1 = нет */
    int                  ipc_fd;
    time_t               start_time;
    uint64_t             connections_total;
} EburNetState;

/* Логирование */
void log_init(const char *path, log_level_t min_level);
void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void log_flush(void);
void log_close(void);
void log_set_daemon_mode(bool daemon);

#endif /* EBURNET_H */
