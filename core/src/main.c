#include "4eburnet.h"
#include "constants.h"
#include "resource_manager.h"
#include "device.h"
#include "mem_tier.h"
#include "config.h"
#include "ipc.h"
#include "routing/nftables.h"
#include "routing/policy.h"
#include "routing/tc_fast.h"
#include "proxy/tproxy.h"
#include "proxy/dispatcher.h"
#include "ntp_bootstrap.h"
#include "routing/rules_loader.h"
#include "crypto/tls.h"
#include "dns/dns_server.h"
#include "dns/dns_rules.h"
#include "routing/device_policy.h"
#include "proxy/proxy_group.h"
#include "proxy/rule_provider.h"
#include "proxy/proxy_provider.h"
#include "proxy/rules_engine.h"
#include "geo/geo_loader.h"
#if CONFIG_EBURNET_DPI
#include "dpi/cdn_updater.h"
#include "geo/opencck_updater.h"
#include "dpi/dpi_filter.h"
#include "dpi/dpi_adapt.h"
#endif
#include "http_server.h"
#include "net_utils.h"
#include "stats.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <limits.h>

/* Параметры master epoll */
#define EPOLL_MAX_EVENTS  32
#define EPOLL_TIMEOUT_MS  10

/* Глобальное состояние — доступно из обработчиков сигналов */
static EburNetState state;
static tproxy_state_t tproxy_state;
static dispatcher_state_t dispatcher_state;
static rules_manager_t rules_state;
static dns_server_t dns_state;
static device_manager_t device_state;
static proxy_group_manager_t pgm_state;
static rule_provider_manager_t rpm_state;
static proxy_provider_manager_t ppm_state;

/* DEC-031: bypass DNS IP для прямого резолва провайдеров */
const char *g_dns_bypass_ip = NULL;
static rules_engine_t re_state;
static geo_manager_t geo_state;

/* 3.5.5: Callback для dns_rules: консультирует traffic rules
   при DNS_ACTION_DEFAULT → назначает fake-ip для proxy-доменов. */
static dns_action_t dns_engine_consult(const char *qname)
{
    /* WHY proto=0 dport=0 sport=0 proc_name=NULL: DNS-резолв не знает proto/порты/процесс;
     * AND/SRC-PORT/PROCESS-NAME правила не применяются при DNS lookup. */
    rule_match_result_t r = rules_engine_match(&re_state, qname, NULL, 0, 0, 0, NULL);
    switch (r.type) {
    case RULE_TARGET_GROUP:   return DNS_ACTION_PROXY;
    case RULE_TARGET_REJECT:  return DNS_ACTION_BLOCK;
    case RULE_TARGET_DIRECT:
    default:                  return DNS_ACTION_BYPASS;
    }
}
/* Embedded HTTP dashboard — static во избежание 33KB на стеке */
static HttpServer g_http;

/* Обработчик сигналов завершения */
static void handle_shutdown(int sig)
{
    (void)sig;
    state.running = false;
}

/* Обработчик SIGHUP — перечитка конфига */
static void handle_reload(int sig)
{
    (void)sig;
    state.reload = true;
}

/* Найти первый существующий файл категории с приоритетом форматов.
 * Порядок: .gbin (mmap) → .dat (v2fly protobuf) → .mmdb (MaxMind) → .lst (текст).
 * WHY: пользователь кладёт любой из форматов в /etc/4eburnet/geo/ —
 *      демон сам определяет и загружает без ручной настройки. */
static bool geo_find_path(const char *dir, const char *base,
                           char *buf, int buf_sz)
{
    static const char * const exts[] = {".gbin", ".dat", ".mmdb", ".lst", NULL};
    for (int i = 0; exts[i]; i++) {
        snprintf(buf, buf_sz, "%s/%s%s", dir, base, exts[i]);
        if (access(buf, R_OK) == 0)
            return true;
    }
    return false;
}

/* Загрузить гео-категории для текущего региона */
static void geo_load_region_categories(geo_manager_t *gm,
                                        const EburNetConfig *cfg)
{
    const char *geo_dir = (cfg->geo_dir[0])
        ? cfg->geo_dir : EBURNET_GEO_DIR;

    const char *rl = NULL;
    if (cfg->geo_region[0]) {
        rl = cfg->geo_region;
    } else {
        switch (gm->current_region) {
        case GEO_REGION_RU: rl = "ru"; break;
        case GEO_REGION_CN: rl = "cn"; break;
        case GEO_REGION_US: rl = "us"; break;
        default: break;
        }
    }

    char path[300];
    char cat_name[48];
    if (rl) {
        snprintf(cat_name, sizeof(cat_name), "geoip-%s", rl);
        if (geo_find_path(geo_dir, cat_name, path, sizeof(path)))
            geo_load_category(gm, cat_name, gm->current_region, path);
        else
            log_msg(LOG_WARN, "GeoIP: не найден файл для категории %s (.gbin/.dat/.mmdb/.lst)",
                    cat_name);

        snprintf(cat_name, sizeof(cat_name), "geosite-%s", rl);
        if (geo_find_path(geo_dir, cat_name, path, sizeof(path)))
            geo_load_category(gm, cat_name, gm->current_region, path);
        else
            log_msg(LOG_WARN, "GeoIP: не найден файл для категории %s (.gbin/.dat/.mmdb/.lst)",
                    cat_name);
    }

    /* Антиреклама — если файл существует */
    snprintf(path, sizeof(path), "%s/geosite-ads.lst", geo_dir);
    geo_load_category(gm, "ads", GEO_REGION_UNKNOWN, path);

    /* Трекеры и угрозы — graceful: warn если файл отсутствует */
    snprintf(path, sizeof(path), "%s/geosite-trackers.lst", geo_dir);
    geo_load_category(gm, "trackers", GEO_REGION_UNKNOWN, path);

    snprintf(path, sizeof(path), "%s/geosite-threats.lst", geo_dir);
    geo_load_category(gm, "threats", GEO_REGION_UNKNOWN, path);

    /* opencck CDN-домены — файл необязателен, логирует WARNING при отсутствии */
    snprintf(path, sizeof(path), "%s/opencck-domains.gbin", geo_dir);
    geo_load_category(gm, "opencck", GEO_REGION_UNKNOWN, path);
}

/* Вывод справки */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Использование: %s [опции] [команда]\n"
        "\n"
        "Опции:\n"
        "  -d            запуск в режиме демона\n"
        "  -c <путь>     путь к конфигу (по умолчанию %s)\n"
        "  -v            версия\n"
        "\n"
        "Команды:\n"
        "  status        статус демона\n"
        "  reload        перечитать конфиг\n"
        "  stop          остановить демон\n"
        "  stats         статистика\n",
        prog, EBURNET_CONFIG_PATH);
}

/* Проверка PID-файла — запущен ли уже демон (M-03: O_CLOEXEC) */
static pid_t check_pid_file(void)
{
    int pidfd = open(EBURNET_PID_FILE, O_RDONLY | O_CLOEXEC);
    FILE *f = (pidfd >= 0) ? fdopen(pidfd, "r") : NULL;
    if (!f) {
        if (pidfd >= 0) close(pidfd);
        return 0;  /* файла нет — не запущен */
    }

    pid_t pid = 0;
    int pid_int = 0;
    if (fscanf(f, "%d", &pid_int) == 1 && pid_int > 0) {
        pid = (pid_t)pid_int;
        /* Проверяем, жив ли процесс (не мы сами — procd пишет PID за нас) */
        if (kill(pid, 0) == 0 && pid != getpid()) {
            /* Защита от PID reuse: проверить что это именно 4eburnetd */
            char comm[32] = {0};
            char comm_path[48];
            snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int)pid);
            int cfd = open(comm_path, O_RDONLY | O_CLOEXEC);
            if (cfd >= 0) {
                read(cfd, comm, sizeof(comm) - 1);
                close(cfd);
                char *nl = strchr(comm, '\n');
                if (nl) *nl = '\0';
            }
            if (strcmp(comm, "4eburnetd") == 0) {
                fclose(f);
                return pid;  /* другой экземпляр 4eburnetd жив */
            }
            /* PID занят другим процессом — stale файл, перезаписать */
        }
    }

    fclose(f);
    /* Мёртвый PID-файл — удаляем */
    unlink(EBURNET_PID_FILE);
    return 0;
}

/* Запись PID-файла (M-02: error handling, M-03: O_CLOEXEC) */
static void write_pid_file(void)
{
    int pidfd = open(EBURNET_PID_FILE,
                     O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    FILE *f = (pidfd >= 0) ? fdopen(pidfd, "w") : NULL;
    if (f) {
        if (fprintf(f, "%d\n", getpid()) < 0 || fflush(f) != 0)
            log_msg(LOG_WARN, "PID file: ошибка записи");
        fclose(f);
    } else {
        if (pidfd >= 0) close(pidfd);
    }
}

/* Демонизация через двойной fork */
static void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid > 0)
        exit(0);  /* родитель завершается */

    /* Новая сессия */
    setsid();

    /* Второй fork — отвязка от терминала */
    pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    if (pid > 0)
        exit(0);

    /* Явное перенаправление fd 0/1/2 через dup2 */
    int devnull = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull >= 0) {
        dup2(devnull, STDIN_FILENO);
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        if (devnull > STDERR_FILENO)
            close(devnull);
    }

    umask(0027);
    if (chdir("/") < 0) { /* корневой каталог недоступен */ }
}

/* Обработка IPC-команды (клиентский режим) */
static int handle_client_command(const char *cmd)
{
    /* Маппинг имя → ipc_command_t */
    static const struct { const char *name; ipc_command_t cmd; } map[] = {
        { "status",          IPC_CMD_STATUS          },
        { "reload",          IPC_CMD_RELOAD          },
        { "stop",            IPC_CMD_STOP            },
        { "stats",           IPC_CMD_STATS           },
        { "groups",          IPC_CMD_GROUP_LIST      },
        { "group-test",      IPC_CMD_GROUP_TEST      },
        { "providers",       IPC_CMD_PROVIDER_LIST   },
        { "rules",           IPC_CMD_RULES_LIST      },
        { "geo-status",      IPC_CMD_GEO_STATUS      },
#if CONFIG_EBURNET_DPI
        { "cdn-update",      IPC_CMD_CDN_UPDATE      },
        { "dpi-get",         IPC_CMD_DPI_GET         },
        { "dpi-set",         IPC_CMD_DPI_SET         },
#endif
        { NULL, 0 }
    };

    ipc_command_t ipc_cmd = 0;
    for (int i = 0; map[i].name; i++) {
        if (strcmp(cmd, map[i].name) == 0) {
            ipc_cmd = map[i].cmd;
            break;
        }
    }
    if (!ipc_cmd) {
        fprintf(stderr, "Неизвестная команда: %s\n", cmd);
        return 1;
    }

    /* P4: IPC client buffer — достаточно для groups JSON (122 серверов) */
    size_t bufsz = 65536;
    char *buf = malloc(bufsz);
    if (!buf) { fprintf(stderr, "{\"error\":\"OOM\"}\n"); return 1; }
    if (ipc_send_command(ipc_cmd, buf, bufsz) < 0) {
        free(buf);
        fprintf(stderr, "{\"error\":\"ipc failed\"}\n");
        return 1;
    }

    printf("%s\n", buf);
    free(buf);
    return 0;
}

/* CLI с payload: 4eburnetd --ipc <command> <json_payload> */
static int handle_ipc_with_payload(const char *cmd, const char *payload)
{
    static const struct { const char *name; ipc_command_t cmd; } map[] = {
        { "group-select",    IPC_CMD_GROUP_SELECT    },
        { "provider-update", IPC_CMD_PROVIDER_UPDATE },
        { NULL, 0 }
    };

    ipc_command_t ipc_cmd = 0;
    for (int i = 0; map[i].name; i++) {
        if (strcmp(cmd, map[i].name) == 0) {
            ipc_cmd = map[i].cmd;
            break;
        }
    }
    if (!ipc_cmd) {
        /* Нет payload — fallback на обычный handle_client_command */
        return handle_client_command(cmd);
    }

    char *buf = malloc(4096);
    if (!buf) { fprintf(stderr, "{\"error\":\"OOM\"}\n"); return 1; }
    if (ipc_send_command_payload(ipc_cmd, payload, buf, 4096) < 0) {
        free(buf);
        fprintf(stderr, "{\"error\":\"ipc failed\"}\n");
        return 1;
    }

    printf("%s\n", buf);
    free(buf);
    return 0;
}

/* Определение уровня лога из строки конфига */
static log_level_t parse_log_level(const char *s)
{
    if (strcmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcmp(s, "info") == 0)  return LOG_INFO;
    if (strcmp(s, "warn") == 0)  return LOG_WARN;
    if (strcmp(s, "error") == 0) return LOG_ERROR;
    return LOG_INFO;
}

int main(int argc, char *argv[])
{
    const char *config_path = EBURNET_CONFIG_PATH;
    bool daemon_mode = false;
    int opt;

    /* --ipc обработка ДО getopt (getopt не поддерживает long options) */
    if (argc >= 3 && strcmp(argv[1], "--ipc") == 0) {
        const char *payload = (argc >= 4) ? argv[3] : NULL;
        static char stdin_buf[4096];
        if (!payload && !isatty(STDIN_FILENO)) {
            ssize_t sn = read(STDIN_FILENO, stdin_buf, sizeof(stdin_buf) - 1);
            if (sn > 0) { stdin_buf[sn] = '\0'; payload = stdin_buf; }
        }
        return handle_ipc_with_payload(argv[2], payload);
    }

    while ((opt = getopt(argc, argv, "dc:vh")) != -1) {
        switch (opt) {
        case 'd':
            daemon_mode = true;
            break;
        case 'c':
            config_path = optarg;
            break;
        case 'v':
            printf("%s %s\n", EBURNET_NAME, EBURNET_VERSION);
            return 0;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Позиционная команда (status/stop/reload/stats/groups/...) */
    if (optind < argc) {
        return handle_client_command(argv[optind]);
    }

    /* Проверка на уже запущенный экземпляр */
    pid_t existing_pid = check_pid_file();
    if (existing_pid > 0) {
        fprintf(stderr, "Демон уже запущен (PID %d)\n", existing_pid);
        return 1;
    }

    /* Демонизация, если запрошена */
    if (daemon_mode) {
        daemonize();
        log_set_daemon_mode(true);
    }

    /* Инициализация логирования (пока с уровнем по умолчанию) */
    log_init(EBURNET_LOG_FILE, LOG_INFO);
    log_msg(LOG_INFO, "%s %s запускается", EBURNET_NAME, EBURNET_VERSION);

    /* Runtime mem_tier (G15-2): читает /proc/meminfo один раз при старте,
     * выставляет глобальные лимиты до создания диспетчера/DNS/geo. */
    mem_tier_init();
    g_dispatcher_max_events = mem_tier_dispatcher_max_events();
    g_relay_drain_per_call  = mem_tier_relay_drain_per_call();

    /* Установка времени до инициализации TLS (DEC-019) */
    if (!ntp_time_is_valid()) {
        log_msg(LOG_INFO,
            "Системное время некорректно, запуск HTTP bootstrap...");
        ntp_bootstrap();
    }

    /* Инициализация крипто-подсистемы */
    if (tls_global_init() < 0)
        log_msg(LOG_WARN, "wolfSSL недоступен, TLS протоколы отключены");

    /* Облегчённый CTX для health-check fork процессов (G15-1).
     * Создаётся в parent ДО fork, наследуется через COW в каждый HC child.
     * Освобождается в cleanup (если HC fork активен — child получит свой). */
    if (tls_hc_ctx_init() < 0)
        log_msg(LOG_WARN, "wolfSSL HC CTX не создан, HC будет использовать главный CTX");

    /* Определение профиля устройства (DEC-013) */
    state.profile = device_detect_profile();
    log_msg(LOG_INFO, "Устройство: %s",
            device_profile_name(state.profile));
    log_msg(LOG_INFO, "Лимиты: relay_buf=%zuKB, max_conns=%d, dns_pending=%d",
            device_relay_buf(state.profile) / 1024,
            device_max_conns(state.profile),
            device_dns_pending(state.profile));
    /* Настройка OOM */
    rm_apply_oom_settings();

    /* Загрузка конфигурации на heap (S2: audit_v8) */
    EburNetConfig *cfg_ptr = calloc(1, sizeof(EburNetConfig));
    if (!cfg_ptr) {
        log_msg(LOG_ERROR, "OOM: не удалось выделить EburNetConfig");
        tls_global_cleanup();
        log_close();
        return 1;
    }
    if (config_load(config_path, cfg_ptr) < 0) {
        log_msg(LOG_ERROR, "Не удалось загрузить конфиг, завершение");
        free(cfg_ptr);
        tls_global_cleanup();
        log_close();
        return 1;
    }
    state.config = cfg_ptr;

    /* Переинициализация лога с уровнем из конфига */
    log_close();
    log_init(EBURNET_LOG_FILE, parse_log_level(cfg_ptr->log_level));

    config_dump(cfg_ptr);

    if (!cfg_ptr->enabled) {
        log_msg(LOG_INFO, "Демон отключён в конфиге, завершение");
        tls_global_cleanup();
        config_free(cfg_ptr);
        free(cfg_ptr);
        log_close();
        return 0;
    }

    /* Проверить наличие защитного правила GEOIP,RU,DIRECT в режиме rules */
    if (strcmp(cfg_ptr->mode, "rules") == 0) {
        bool has_ru_direct = false;
        for (int i = 0; i < cfg_ptr->traffic_rule_count; i++) {
            const TrafficRule *tr = &cfg_ptr->traffic_rules[i];
            if (tr->type == RULE_TYPE_GEOIP &&
                strcasecmp(tr->value, "RU") == 0 &&
                strcasecmp(tr->target, "DIRECT") == 0) {
                has_ru_direct = true;
                break;
            }
        }
        if (!has_ru_direct) {
            log_msg(LOG_WARN,
                "SECURITY: нет правила GEOIP,RU,DIRECT. "
                "RU трафик идёт через прокси — паттерн трафика "
                "может раскрыть IP вашего сервера. "
                "Добавьте правило в LuCI: Services → 4eburNet → Rules.");
        }
    }

    /* Запись PID-файла */
    write_pid_file();

    /* Инициализация IPC */
    state.ipc_fd = ipc_init();
    if (state.ipc_fd < 0) {
        log_msg(LOG_ERROR, "Не удалось создать IPC сокет");
        tls_global_cleanup();
        config_free(cfg_ptr);
        free(cfg_ptr);
        unlink(EBURNET_PID_FILE);
        log_close();
        return 1;
    }

    /* B7-01: master_epoll объявлен до init-блока —
     * goto cleanup безопасен из любой точки инициализации */
    int master_epoll = -1;

    /* Инициализация таблиц маршрутизации */
    if (nft_init() != NFT_OK) {
        log_msg(LOG_WARN,
            "nftables недоступен, маршрутизация отключена");
    } else {
        log_msg(LOG_INFO,
            "TPROXY: используется mark-based routing "
            "(fwmark=0x01, table=100, без kmod-nft-tproxy)");

        nft_result_t mode_rc;
        if (strcmp(cfg_ptr->mode, "global") == 0)
            mode_rc = nft_mode_set_global();
        else if (strcmp(cfg_ptr->mode, "direct") == 0)
            mode_rc = nft_mode_set_direct();
        else
            mode_rc = nft_mode_set_rules(cfg_ptr->dns.fake_ip_range,
                                             cfg_ptr->dns.fake_ip6_range);

        if (mode_rc != NFT_OK) {
            log_msg(LOG_ERROR, "nftables: режим '%s' не применён — "
                "остановка во избежание fail-open", cfg_ptr->mode);
            nft_cleanup();
            goto cleanup;
        }

        /* DNAT redirect для fake-IP (fallback когда kmod-nft-tproxy отсутствует) */
        nft_dnat_setup(NFT_TPROXY_PORT,
                       cfg_ptr->dns.fake_ip_range,
                       cfg_ptr->dns.fake_ip6_range);

        /* ip_cidr / ip_cidr6 правила нацеленные на прокси: добавить mark + DNAT.
         * Иначе реальные IP (Telegram и пр.) идут мимо :7893 после mark. */
        for (int i = 0; i < cfg_ptr->traffic_rule_count; i++) {
            const TrafficRule *tr = &cfg_ptr->traffic_rules[i];
            if (tr->type != RULE_TYPE_IP_CIDR && tr->type != RULE_TYPE_IP_CIDR6)
                continue;
            if (strcmp(tr->target, "DIRECT") == 0 ||
                strcmp(tr->target, "REJECT") == 0)
                continue;
            if (tr->type == RULE_TYPE_IP_CIDR) {
                nft_set_add_addr(NFT_SET_PROXY, tr->value);
                nft_dnat_add_cidr4(tr->value, NFT_TPROXY_PORT);
            } else {
                /* WHY: IPv6 CIDR → ip6 eburnet_nat6; nft_dnat_add_cidr4 на IPv6 → ERROR */
                nft_set_add_addr(NFT_SET_PROXY6, tr->value);
                nft_dnat_add_cidr6(tr->value, NFT_TPROXY_PORT);
            }
        }
    }

    /* Verdict Maps для масштабируемой маршрутизации (DEC-017) */
    if (nft_vmap_create() != NFT_OK)
        log_msg(LOG_WARN, "nft: verdict maps не созданы");

    /* HW Offload bypass (DEC-018) */
    if (nft_offload_bypass_init() != NFT_OK)
        log_msg(LOG_WARN, "nft: offload bypass не инициализирован");

    /* Flow offload для DIRECT трафика (v1.1-3) */
    if (cfg_ptr->flow_offload) {
        if (nft_flow_offload_enable(cfg_ptr->lan_interface[0]
                                    ? cfg_ptr->lan_interface : NULL) < 0)
            log_msg(LOG_WARN, "flow offload: не активирован (software path)");
    }
    /* TC ingress fast path: cls_u32 LAN bypass (v1.2-2) */
    if (cfg_ptr->tc_fast_enabled) {
        if (tc_fast_enable(cfg_ptr->lan_interface[0] ? cfg_ptr->lan_interface : "br-lan",
                           cfg_ptr->lan_prefix, cfg_ptr->lan_mask) < 0)
            log_msg(LOG_WARN, "tc_fast: не активирован");
    }
    /* MTU LAN интерфейса (0 = не менять) */
    if (cfg_ptr->mtu > 0 && cfg_ptr->lan_interface[0]) {
        static char mtu_arg[8];
        snprintf(mtu_arg, sizeof(mtu_arg), "%u", (unsigned)cfg_ptr->mtu);
        const char *const av[] = {"ip","link","set","dev",cfg_ptr->lan_interface,
                                   "mtu",mtu_arg,NULL};
        if (exec_cmd_safe(av,NULL,0) < 0)
            log_msg(LOG_WARN, "mtu: ip link set dev %s mtu %u провалился",
                    cfg_ptr->lan_interface, (unsigned)cfg_ptr->mtu);
        else
            log_msg(LOG_INFO, "mtu: %s mtu %u", cfg_ptr->lan_interface,
                    (unsigned)cfg_ptr->mtu);
    }

    /* Менеджер правил маршрутизации */
    if (rules_init(&rules_state) < 0) {
        log_msg(LOG_ERROR, "rules: инициализация провалилась");
        goto cleanup;
    }

    /* L-09: PATH_MAX на heap вместо стека */
    char *bypass_file = malloc(PATH_MAX);
    char *proxy_file = malloc(PATH_MAX);
    if (!bypass_file || !proxy_file) {
        free(bypass_file); free(proxy_file);
        log_msg(LOG_WARN, "Не удалось выделить память для путей правил");
    } else {
        int bp_n = snprintf(bypass_file, PATH_MAX,
                            "%s/bypass.cidr", EBURNET_RULES_DIR);
        int pr_n = snprintf(proxy_file, PATH_MAX,
                            "%s/proxy.cidr", EBURNET_RULES_DIR);
        if (bp_n < 0 || (size_t)bp_n >= PATH_MAX ||
            pr_n < 0 || (size_t)pr_n >= PATH_MAX)
            log_msg(LOG_WARN, "Путь правил обрезан");

        log_msg(LOG_WARN,
            "rules: файл правил не найден: %s "
            "— маршрутизация только через geo и rule_set",
            bypass_file);

        rules_add_source(&rules_state, bypass_file, RULES_BYPASS);
        rules_add_source(&rules_state, proxy_file,  RULES_PROXY);
        rules_load_all(&rules_state);
        free(bypass_file);
        free(proxy_file);
    }

    /* DNS демон — init (register_epoll после master_epoll) */
    if (cfg_ptr->dns.enabled) {
        if (dns_rules_init(cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "dns_rules: инициализация провалилась");
            goto cleanup;
        }
        if (dns_server_init(&dns_state, cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "dns_server: инициализация провалилась");
            goto cleanup;
        }

        /* B-09: проверить upstream DNS доступность (warning, не блокирует старт) */
        if (cfg_ptr->dns.upstream_default[0]) {
            int probe_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (probe_fd >= 0) {
                struct timeval ptv = { .tv_sec = TIMEOUT_DNS_PROBE_SEC, .tv_usec = 0 };
                setsockopt(probe_fd, SOL_SOCKET, SO_RCVTIMEO,
                           &ptv, sizeof(ptv));
                uint16_t up_port = cfg_ptr->dns.upstream_port
                                   ? cfg_ptr->dns.upstream_port : DNS_PORT;
                struct sockaddr_in sa = {
                    .sin_family = AF_INET,
                    .sin_port   = htons(up_port),
                };
                if (inet_pton(AF_INET, cfg_ptr->dns.upstream_default,
                              &sa.sin_addr) == 1) {
                    log_msg(LOG_INFO, "DNS: probe upstream %s:%u",
                            cfg_ptr->dns.upstream_default, up_port);
                    /* Минимальный DNS запрос: QNAME="." QTYPE=A QCLASS=IN */
                    uint8_t probe[] = {
                        0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00,
                        0x00,0x00, 0x00,0x00, 0x00,
                        0x00,0x01, 0x00,0x01 };
                    if (sendto(probe_fd, probe, sizeof(probe), 0,
                               (struct sockaddr *)&sa, sizeof(sa)) > 0) {
                        uint8_t resp[64];
                        ssize_t pn = recv(probe_fd, resp, sizeof(resp), 0);
                        if (pn <= 0)
                            log_msg(LOG_WARN,
                                "DNS: upstream %s:%u недоступен при старте"
                                " — DNS может не работать до появления сети",
                                cfg_ptr->dns.upstream_default, up_port);
                    }
                }
                close(probe_fd);
            }
        }
    }

    /* Per-device routing (netdev MAC map).
     * WHY: инициализация памяти не требует lan_interface — только nftables apply. */
    if (cfg_ptr->device_count > 0) {
        if (device_policy_init(&device_state, cfg_ptr) < 0)
            log_msg(LOG_WARN, "device_policy: инициализация провалилась");
        else if (cfg_ptr->lan_interface[0])
            device_policy_apply(&device_state, cfg_ptr->lan_interface);
    }

    /* Политика маршрутизации — ip rule и ip route
     * B3-01: при холодной загрузке WAN может не быть —
     * hotplug (40-4eburnet) восстановит ip rules при ifup */
    policy_check_conflicts();
    if (strcmp(cfg_ptr->mode, "direct") == 0) {
        /* в direct режиме правила маршрутизации не нужны */
    } else {
        /* rules и global используют TPROXY */
        if (policy_init_tproxy() != POLICY_OK)
            log_msg(LOG_WARN, "policy: TPROXY routing не применён — "
                "hotplug восстановит при поднятии WAN");
    }
    policy_dump();

    /* Запуск TPROXY сервера */
    if (tproxy_init(&tproxy_state, NFT_TPROXY_PORT,
                    state.profile) < 0) {
        log_msg(LOG_WARN,
            "TPROXY недоступен, перехват трафика отключён");
    }

    /* Инициализация диспетчера relay */
    if (dispatcher_init(&dispatcher_state, state.profile) < 0) {
        log_msg(LOG_WARN, "Диспетчер не запущен");
    } else {
        dispatcher_set_context(&dispatcher_state, cfg_ptr);

        /* P2: providers ДО groups — серверы должны быть загружены
         * к моменту proxy_group_init (groups итерирует provider_servers) */
        if (rule_provider_init(&rpm_state, cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "rule_provider: инициализация провалилась");
            goto cleanup;
        }
        rule_provider_load_all(&rpm_state);
        /* DEC-031: bypass DNS IP для прямого резолва провайдеров */
        g_dns_bypass_ip = cfg_ptr->dns.upstream_bypass[0]
                          ? cfg_ptr->dns.upstream_bypass
                          : cfg_ptr->dns.upstream_default;
        if (proxy_provider_init(&ppm_state, cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "proxy_provider: инициализация провалилась");
            goto cleanup;
        }
        proxy_provider_load_all(&ppm_state);
        /* Groups после providers — видят provider_servers.
         * first_start=true: HC stagger включается для url-test групп. */
        if (proxy_group_init(&pgm_state, cfg_ptr, true) < 0) {
            log_msg(LOG_ERROR, "proxy_group: инициализация провалилась");
            goto cleanup;
        }
        /* Pre-warm DNS кэш для всех upstream-серверов. Блокирует на N×~100ms
         * один раз при старте — потом dispatcher_resolve_server всегда cache
         * hit. Без pre-warm dispatcher_tick зашкаливал до 1041мс при первом
         * relay через каждый сервер (recv в event loop). */
        dispatcher_prewarm_resolve(&pgm_state, cfg_ptr);
        if (geo_manager_init(&geo_state, cfg_ptr) == 0) {
            geo_load_region_categories(&geo_state, cfg_ptr);
            /* B5-01: предупредить при пустых geo-данных в режиме rules */
            bool any_loaded = false;
            for (int gi = 0; gi < geo_state.count; gi++)
                if (geo_state.categories[gi].loaded) { any_loaded = true; break; }
            if (!any_loaded && strcmp(cfg_ptr->mode, "rules") == 0)
                log_msg(LOG_WARN, "GeoIP: наборы данных пусты — "
                    "в режиме rules трафик может не перехватываться");
            http_server_set_geo_loaded(any_loaded);
            http_server_set_geo_manager(&geo_state);
        } else {
            log_msg(LOG_WARN, "GeoIP: не удалось инициализировать");
            http_server_set_geo_loaded(false);
            http_server_set_geo_manager(NULL);
        }
        if (rules_engine_init(&re_state, cfg_ptr, &pgm_state, &rpm_state,
                              &geo_state) < 0) {
            log_msg(LOG_ERROR, "rules_engine: инициализация провалилась");
            goto cleanup;
        }
        dispatcher_set_rules_engine(&re_state);
        dispatcher_set_pgm(&pgm_state);
        http_server_set_re(&re_state);
        ipc_set_3x_context(&pgm_state, &rpm_state, &re_state, &geo_state);
        /* A3: geo_manager для adblock категоризации в DNS */
        dns_state.geo_manager = &geo_state;
        /* 3.5.1: GEOSITE блокировка — связать geo с dns_rules */
        dns_rules_set_geo_manager(&geo_state);
        if (cfg_ptr->dns.block_geosite_ads)
            dns_rules_add_geosite(GEO_CAT_ADS,      DNS_ACTION_BLOCK);
        if (cfg_ptr->dns.block_geosite_trackers)
            dns_rules_add_geosite(GEO_CAT_TRACKERS,  DNS_ACTION_BLOCK);
        if (cfg_ptr->dns.block_geosite_threats)
            dns_rules_add_geosite(GEO_CAT_THREATS,   DNS_ACTION_BLOCK);
        /* 3.5.5: Traffic rules consultation — fake-ip для opencck_domains */
        dns_rules_set_engine(dns_engine_consult);
    }

    /* Установка обработчиков сигналов (M-10: SA_RESTART) */
    struct sigaction sa_shutdown = {
        .sa_handler = handle_shutdown,
        .sa_flags   = SA_RESTART,
    };
    struct sigaction sa_reload = {
        .sa_handler = handle_reload,
        .sa_flags   = SA_RESTART,
    };
    sigemptyset(&sa_shutdown.sa_mask);
    sigemptyset(&sa_reload.sa_mask);
    sigaction(SIGTERM, &sa_shutdown, NULL);
    sigaction(SIGINT,  &sa_shutdown, NULL);
    /* WHY: SIGHUP = reload конфига во всех режимах запуска.
     * procd запускает без -d → daemon_mode=false, поэтому условие убрано.
     * SSH-disconnect SIGHUP не дойдёт до фонового процесса без ctty. */
    sigaction(SIGHUP,  &sa_reload,  NULL);

    /* M-12: sigaction вместо signal для SIGPIPE */
    struct sigaction sa_pipe = { .sa_handler = SIG_IGN, .sa_flags = 0 };
    sigemptyset(&sa_pipe.sa_mask);
    sigaction(SIGPIPE, &sa_pipe, NULL);

    /* SIGCHLD: авто-reap zombie процессов от net_spawn_fetch/tcp_ping (audit_v9) */
    struct sigaction sa_chld = {0};
    sa_chld.sa_handler = SIG_DFL;
    sa_chld.sa_flags   = SA_NOCLDWAIT;
    sigemptyset(&sa_chld.sa_mask);
    sigaction(SIGCHLD, &sa_chld, NULL);

    /* Master epoll: один epoll_wait вместо 3 отдельных + usleep (H-01/H-10) */
    master_epoll = epoll_create1(EPOLL_CLOEXEC);
    if (master_epoll < 0) {
        log_msg(LOG_ERROR, "epoll_create1: %s", strerror(errno));
        /* fallback невозможен — завершаем */
        goto cleanup;
    }

    /* Регистрируем listen fd в master epoll */
    struct epoll_event mev = {0};
    int listen_fds[] = {
        tproxy_state.tcp4_fd, tproxy_state.tcp6_fd,
        tproxy_state.udp4_fd, tproxy_state.udp6_fd,
        state.ipc_fd
    };
    for (int i = 0; i < 5; i++) {
        if (listen_fds[i] < 0) continue;
        mev.events  = EPOLLIN;
        mev.data.fd = listen_fds[i];
        if (epoll_ctl(master_epoll, EPOLL_CTL_ADD, listen_fds[i], &mev) < 0) {
            log_msg(LOG_WARN, "epoll_ctl ADD fd %d: %s",
                    listen_fds[i], strerror(errno));
        }
    }

    /* DNS fd в master epoll */
    if (cfg_ptr->dns.enabled && dns_state.udp_fd >= 0)
        dns_server_register_epoll(&dns_state, master_epoll);

    /* HTTP dashboard — не фатально если порт занят */
    if (http_server_init(&g_http) == 0) {
        http_server_set_config(cfg_ptr);
        http_server_set_pgm(&pgm_state);
        http_server_set_rpm(&rpm_state);
        http_server_set_dm(&device_state);
        http_server_set_dispatcher(&dispatcher_state);
        dispatcher_set_dm(&device_state);
        http_server_register_epoll(&g_http, master_epoll);
        log_msg(LOG_INFO, "HTTP dashboard: порт %d", HTTP_PORT);
    } else {
        log_msg(LOG_WARN, "HTTP dashboard: не удалось запустить на порту %d",
                HTTP_PORT);
    }

    /* Fake-IP: передать таблицу диспетчеру для reverse lookup */
#if CONFIG_EBURNET_FAKE_IP
    if (dns_state.fake_ip_ready)
        dispatcher_set_fake_ip(&dns_state.fake_ip);
#endif

    /* Главный цикл */
    state.running    = true;
    state.reload     = false;
    state.start_time = time(NULL);
    state.connections_total = 0;
    state.cdn_pipe_fd   = -1;
    state.cdn_next_check = 0;

    log_msg(LOG_INFO, "Главный цикл запущен (master epoll)");

    /* Первичное заполнение кэша до начала цикла */
    http_server_write_servers_cache();
    http_server_write_dns_cache();

    /* Spin-детектор: считаем итерации в которых epoll не спал (n>0 сразу) */
#ifdef __mips__
    static uint32_t _spin_iters = 0;
    static time_t   _spin_t0    = 0;
#endif

    while (state.running) {
        /* Единственный blocking wait — 10мс таймаут */
        struct epoll_event events[EPOLL_MAX_EVENTS];
        int n = epoll_wait(master_epoll, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);
#ifdef __mips__
        if (n > 0) {
            _spin_iters++;
            time_t _tnow = time(NULL);
            if (_spin_t0 == 0) _spin_t0 = _tnow;
            if (_tnow - _spin_t0 >= 2) {
                log_msg(LOG_DEBUG, "SPIN: master_epoll=%u events/2s fd0=%d ev0=0x%x",
                        _spin_iters, events[0].data.fd, events[0].events);
                _spin_iters = 0; _spin_t0 = _tnow;
            }
        } else {
            _spin_iters = 0; _spin_t0 = 0;
        }
#endif

        /* MIPS throttle: wolfSSL_connect (X25519 keygen) занимает ~150ms без HW AES.
         * Ограничиваем до 2 TLS handshake за тик. При превышении лимита временно
         * убираем fd из epoll (DEL), сохраняем в deferred[], после цикла — ADD обратно.
         * WHY DEL+ADD а не просто continue: с LT-epoll пропущенное готовое событие
         * немедленно возвращается в следующем epoll_wait → tight busy-loop → 100% CPU. */
#ifdef __mips__
#define DNS_TLS_HS_PER_TICK  2
        int dns_tls_hs_tick  = 0;
        void *deferred_tls[DNS_ASYNC_POOL_SIZE];
        int   deferred_count = 0;
#endif

        for (int i = 0; i < n; i++) {
            /* IPC client (data.ptr) — ПЕРВЫМ: data.fd при ptr = мусорный int */
            if (ipc_is_client_ptr(events[i].data.ptr)) {
                ipc_client_event(events[i].data.ptr,
                                 events[i].events, &state);
                continue;
            }

            /* HTTP dashboard */
            if (http_server_handle(&g_http, events[i].data.fd,
                                   master_epoll, events[i].events) == 0)
                continue;

            /* Async DoH/DoT — epoll data.ptr, не data.fd */
            if (cfg_ptr->dns.enabled && dns_state.initialized) {
                void *ptr = events[i].data.ptr;
                if (dns_server_is_async_ptr(&dns_state, ptr)) {
#ifdef __mips__
                    if (dns_server_async_in_tls_hs(ptr) &&
                        dns_tls_hs_tick >= DNS_TLS_HS_PER_TICK) {
                        /* Откладываем: убираем из epoll, добавим обратно после цикла */
                        async_dns_conn_t *_c = (async_dns_conn_t *)ptr;
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL, _c->fd, NULL);
                        if (deferred_count < DNS_ASYNC_POOL_SIZE)
                            deferred_tls[deferred_count++] = ptr;
                        continue;
                    }
                    if (dns_server_async_in_tls_hs(ptr))
                        dns_tls_hs_tick++;
#endif
                    dns_server_handle_async_event(&dns_state, ptr,
                                                  events[i].events);
                    continue;
                }
            }

            int fd = events[i].data.fd;
            if (fd == state.ipc_fd) {
                ipc_accept(state.ipc_fd, &state, master_epoll);
            } else if (cfg_ptr->dns.enabled &&
                       dns_server_is_pending_fd(&dns_state, fd)) {
                /* Ответ от upstream DNS или TCP DNS клиент */
                dns_server_handle_event(&dns_state, fd, master_epoll,
                                        events[i].events);
            } else if (dns_state.initialized &&
                       (fd == dns_state.udp_fd || fd == dns_state.tcp_fd)) {
                dns_server_handle_event(&dns_state, fd, master_epoll,
                                        events[i].events);
            } else if (rule_provider_owns_fd(&rpm_state, fd)) {
                /* Результат async fetch правил */
                epoll_ctl(master_epoll, EPOLL_CTL_DEL, fd, NULL);
                rule_provider_handle_fetch(&rpm_state, fd, events[i].events);
            } else if (proxy_provider_owns_fd(&ppm_state, fd)) {
                /* Результат async fetch proxy-провайдера */
                epoll_ctl(master_epoll, EPOLL_CTL_DEL, fd, NULL);
                if (proxy_provider_handle_fetch(&ppm_state, fd, events[i].events))
                    proxy_group_restore_all_selections(&pgm_state);
#if CONFIG_EBURNET_DPI
            } else if (state.cdn_pipe_fd >= 0 && fd == state.cdn_pipe_fd) {
                /* Результат async CDN update */
                char rbuf[8] = {0};
                ssize_t rn = read(state.cdn_pipe_fd, rbuf, sizeof(rbuf) - 1);
                epoll_ctl(master_epoll, EPOLL_CTL_DEL,
                          state.cdn_pipe_fd, NULL);
                close(state.cdn_pipe_fd);
                state.cdn_pipe_fd = -1;
                if (rn > 0 && rbuf[0] == 'O') {
                    const char *ddir = (cfg_ptr && cfg_ptr->dpi_dir[0])
                                       ? cfg_ptr->dpi_dir
                                       : EBURNET_DPI_DIR;
                    dpi_filter_init(ddir);
                    log_msg(LOG_INFO,
                            "CDN IP обновлены, dpi_filter перезагружен");
                } else {
                    log_msg(LOG_WARN,
                            "CDN update завершился с ошибкой");
                }
#endif
            } else {
                /* Проверить proxy_group health-check pipe */
                bool hc_done = false;
                for (int g = 0; g < pgm_state.count; g++) {
                    if (proxy_group_owns_fd(&pgm_state.groups[g], fd)) {
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL, fd, NULL);
                        proxy_group_handle_hc_event(&pgm_state,
                                                    &pgm_state.groups[g],
                                                    fd, events[i].events,
                                                    pgm_state.cfg);
                        hc_done = true;
                        break;
                    }
                }
                if (!hc_done) {
                    /* WHY: ptr-based события (data.ptr) печатаются как fd=<addr>.
                     * Значения > 65535 — это точно указатели, не файловые дескрипторы.
                     * Такое событие не должно было дойти сюда; DEL по garbage fd
                     * небезопасен. Снимаем через DEL по data.fd в надежде что это
                     * совпадёт, иначе просто логируем и пропускаем. */
                    if ((uintptr_t)events[i].data.ptr > 65535u) {
                        log_msg(LOG_WARN,
                            "master: неизвестный ptr-event ptr=%p ev=0x%x — "
                            "снимаю из epoll",
                            events[i].data.ptr, events[i].events);
                        /* ptr содержит fd в data.fd (union) на 32-bit MIPS */
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL, fd, NULL);
                    } else {
                        tproxy_handle_event(&tproxy_state, fd);
                    }
                }
            }
        }

#ifdef __mips__
        /* Возвращаем отложенные TLS_HS соединения в epoll — обработаем на следующем тике.
         * WHY: CONNECTING ждёт EPOLLOUT (TCP handshake), TLS_HS ждёт EPOLLIN (ServerHello).
         * CONNECTING: EPOLLONESHOT — сокет всегда writable после connect() → LT без
         * ONESHOT = busy-spin каждый epoll_wait → 100% CPU → DNS recv-Q переполняется.
         * EPOLLONESHOT гарантирует ровно ОДИН wake-up, затем fd автоматически отключается.
         * TLS_HS: обычный LT EPOLLIN — data-driven, spin невозможен (нет данных = нет события). */
        for (int _d = 0; _d < deferred_count; _d++) {
            async_dns_conn_t *_c = (async_dns_conn_t *)deferred_tls[_d];
            if (_c->fd >= 0) {
                uint32_t _want = (_c->state == ASYNC_DNS_CONNECTING)
                    ? (EPOLLOUT | EPOLLERR | EPOLLHUP | EPOLLONESHOT)
                    : (EPOLLIN  | EPOLLERR | EPOLLHUP);
                struct epoll_event _ev = { .events = _want, .data.ptr = _c };
                epoll_ctl(master_epoll, EPOLL_CTL_ADD, _c->fd, &_ev);
            }
        }
#endif

        /* WS /memory broadcast каждую секунду (100 тиков × 10мс) */
        if (dispatcher_state.tick_count % 100 == 0)
            http_server_broadcast_tick(&g_http, master_epoll);

        /* HTTP таймаут соединений — каждые ~5 сек (500 тиков × 10мс) */
        if (dispatcher_state.tick_count % 500 == 0)
            http_server_tick(&g_http, master_epoll);

        /* Кешировать IPC данные в /tmp для HTTP dashboard
           (избегаем popen("4eburnetd --ipc") внутри демона — дедлок)
           Записывать каждые ~3 сек (300 тиков × 10мс).            */
        if (dispatcher_state.tick_count % 300 == 0) {
            /* /tmp/4eburnet-stats.json — читается HTTP /api/stats */
            char stats_json[256];
            int sn = snprintf(stats_json, sizeof(stats_json),
                "{\"connections_total\":%llu,\"connections_active\":%llu,"
                "\"dns_queries\":%llu,\"dns_cached\":%llu,"
                "\"blocked_ads\":%llu,\"blocked_trackers\":%llu,"
                "\"blocked_threats\":%llu}",
                (unsigned long long)atomic_load(&g_stats.connections_total),
                (unsigned long long)atomic_load(&g_stats.connections_active),
                (unsigned long long)atomic_load(&g_stats.dns_queries_total),
                (unsigned long long)atomic_load(&g_stats.dns_cached_total),
                (unsigned long long)atomic_load(&g_stats.blocked_ads),
                (unsigned long long)atomic_load(&g_stats.blocked_trackers),
                (unsigned long long)atomic_load(&g_stats.blocked_threats));
            if (sn > 0) {
                FILE *sf = fopen("/tmp/4eburnet-stats.json", "w");
                if (sf) { fwrite(stats_json, 1, (size_t)sn, sf); fclose(sf); }
            }
            /* /tmp/4eburnet-groups.json — proxy_group_to_json() напрямую,
               без fork/popen (дедлок при вызове демона из себя). */
            if (pgm_state.count > 0) {
                static char grp_json_buf[65536]; /* IPC_RESPONSE_MAX */
                proxy_group_to_json(&pgm_state, grp_json_buf, sizeof(grp_json_buf));
                FILE *gf = fopen("/tmp/4eburnet-groups.json.tmp", "w");
                if (gf) {
                    if (fputs(grp_json_buf, gf) == EOF) {
                        log_msg(LOG_WARN, "groups.json: ошибка записи");
                        fclose(gf);
                        unlink("/tmp/4eburnet-groups.json.tmp");
                    } else {
                        fclose(gf);
                        if (rename("/tmp/4eburnet-groups.json.tmp",
                                   "/tmp/4eburnet-groups.json") != 0)
                            log_msg(LOG_WARN, "groups.json: rename: %s",
                                    strerror(errno));
                    }
                }
            }
        }

        /* DNS pending таймауты — каждый тик (10ms), CLOCK_MONOTONIC дёшев (L-07) */
        if (cfg_ptr->dns.enabled && dns_state.initialized)
            dns_server_check_pending_timeouts(&dns_state);

        /* Async DoH/DoT таймауты — каждые ~100мс (10 тиков × 10мс) */
        if (cfg_ptr->dns.enabled && dns_state.initialized &&
            dispatcher_state.tick_count % 10 == 0)
            dns_server_check_async_timeouts(&dns_state);

        /* TCP DNS клиент таймауты — каждые ~500мс (50 тиков × 10мс) */
        if (cfg_ptr->dns.enabled && dns_state.initialized &&
            dispatcher_state.tick_count % 50 == 0)
            dns_server_check_tcp_timeouts(&dns_state);

        /* Fake-IP TTL eviction — каждые ~60 сек (6000 тиков × 10мс) */
#if CONFIG_EBURNET_FAKE_IP
        if (dns_state.fake_ip_ready &&
            dispatcher_state.tick_count % 6000 == 0 &&
            dispatcher_state.tick_count > 0)
            fake_ip_evict_expired(&dns_state.fake_ip);
#endif

        /* opencck автообновление — каждые ~60 сек (6000 тиков × 10мс) */
        if (dispatcher_state.tick_count % 6000 == 0 &&
            dispatcher_state.tick_count > 0) {
            const char *geo_dir = (cfg_ptr->geo_dir[0])
                ? cfg_ptr->geo_dir : EBURNET_GEO_DIR;
            opencck_updater_tick(geo_dir,
                                 cfg_ptr->opencck_url,
                                 cfg_ptr->opencck_update_interval_s);
        }

        /* Relay события в своём epoll — timeout=0, не блокирует */
        dispatcher_tick(&dispatcher_state);

        /* Периодические задачи: health-check групп и обновление провайдеров.
         * tick_count инкрементируется в dispatcher_tick, здесь проверяем
         * каждые ~30 сек (3000 тиков × 10мс) */
        if (dispatcher_state.tick_count % 3000 == 0 &&
            dispatcher_state.tick_count > 0) {
            proxy_group_tick(&pgm_state);
            rule_provider_tick(&rpm_state);
            proxy_provider_tick(&ppm_state);
            http_server_write_servers_cache();
            http_server_write_dns_cache();

            /* Зарегистрировать новые pipe fd в master epoll (все слоты) */
            for (int gi = 0; gi < pgm_state.count; gi++) {
                proxy_group_state_t *gs = &pgm_state.groups[gi];
                for (int si = 0; si < PROXY_GROUP_HC_SLOTS; si++) {
                    if (gs->hc_slots[si].pipe_fd >= 0 &&
                        !gs->hc_slots[si].registered) {
                        struct epoll_event pev = {
                            .events  = EPOLLIN | EPOLLHUP,
                            .data.fd = gs->hc_slots[si].pipe_fd,
                        };
                        epoll_ctl(master_epoll, EPOLL_CTL_ADD,
                                  gs->hc_slots[si].pipe_fd, &pev);
                        gs->hc_slots[si].registered = true;
                    }
                }
            }
            for (int ri = 0; ri < rpm_state.count; ri++) {
                rule_provider_state_t *ps = &rpm_state.providers[ri];
                if (ps->fetch_pipe_fd >= 0 && !ps->fetch_registered) {
                    struct epoll_event pev = {
                        .events  = EPOLLIN | EPOLLHUP,
                        .data.fd = ps->fetch_pipe_fd,
                    };
                    epoll_ctl(master_epoll, EPOLL_CTL_ADD,
                              ps->fetch_pipe_fd, &pev);
                    ps->fetch_registered = true;
                }
            }
            for (int pi = 0; pi < ppm_state.count; pi++) {
                proxy_provider_state_t *pps = &ppm_state.providers[pi];
                if (pps->fetch_pipe_fd >= 0 && !pps->fetch_registered) {
                    struct epoll_event pev = {
                        .events  = EPOLLIN | EPOLLHUP,
                        .data.fd = pps->fetch_pipe_fd,
                    };
                    epoll_ctl(master_epoll, EPOLL_CTL_ADD,
                              pps->fetch_pipe_fd, &pev);
                    pps->fetch_registered = true;
                }
            }
        }

        /* Перезагрузка конфига по сигналу или IPC команде */
        if (state.reload) {
            log_msg(LOG_INFO, "Перезагрузка конфигурации...");
            EburNetConfig *new_cfg_ptr = calloc(1, sizeof(EburNetConfig));
            if (new_cfg_ptr && config_load(config_path, new_cfg_ptr) == 0) {
                /* H-09a: сохранить DNS порт ДО освобождения старого конфига */
                uint16_t old_dns_port = cfg_ptr->dns.listen_port
                    ? cfg_ptr->dns.listen_port : 53;
                config_free(cfg_ptr);
                free(cfg_ptr);
                cfg_ptr = new_cfg_ptr;
                state.config = cfg_ptr;
                config_dump(cfg_ptr);
                http_server_reload_token();
                dispatcher_set_context(&dispatcher_state, cfg_ptr);
                rules_check_update(&rules_state);
                /* H-09: DNS реинициализация при reload.
                 * WHY: rebind :53 при неизменном порте вызывает EADDRINUSE race —
                 * dnsmasq успевает занять порт в окне между close() и bind().
                 * Если порт не изменился — только обновляем cfg ptr и cache настройки,
                 * сокеты не трогаем. Полный rebind только при смене порта или
                 * отключении DNS. */
                uint16_t new_dns_port = cfg_ptr->dns.listen_port
                    ? cfg_ptr->dns.listen_port : 53;
                bool dns_port_unchanged = dns_state.initialized
                    && cfg_ptr->dns.enabled
                    && (old_dns_port == new_dns_port);
                if (dns_state.initialized && !dns_port_unchanged) {
                    if (dns_state.udp_fd >= 0)
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL,
                                  dns_state.udp_fd, NULL);
                    if (dns_state.tcp_fd >= 0)
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL,
                                  dns_state.tcp_fd, NULL);
                    dns_server_cleanup(&dns_state);
                } else if (dns_port_unchanged) {
                    log_msg(LOG_INFO,
                        "reload: DNS порт %u не изменился, rebind пропущен",
                        new_dns_port);
                    dns_state.cfg = cfg_ptr;
                    dns_state.cache.stale_enabled =
                        cfg_ptr->dns.stale_while_revalidate;
                    dns_state.cache.grace_seconds =
                        cfg_ptr->dns.stale_grace_seconds;
                    /* WHY: fake_ip_table хранит raw EburNetConfig* и читает
                     * cfg->dns.fake_ip_ttl при каждом запросе. Без обновления —
                     * dangling pointer после config_free → SIGSEGV. */
#if CONFIG_EBURNET_FAKE_IP
                    if (dns_state.fake_ip_ready)
                        dns_state.fake_ip.cfg = cfg_ptr;
#endif
                }
                dns_rules_free();
                if (cfg_ptr->dns.enabled) {
                    if (dns_rules_init(cfg_ptr) < 0)
                        log_msg(LOG_WARN,
                            "reload: dns_rules_init провалился — правила DNS могут быть неполными");
                    if (!dns_port_unchanged) {
                        if (dns_server_init(&dns_state, cfg_ptr) == 0)
                            dns_server_register_epoll(&dns_state, master_epoll);
                    }
                }
                /* Обновить fake-ip указатель в dispatcher после reload */
#if CONFIG_EBURNET_FAKE_IP
                dispatcher_set_fake_ip(
                    dns_state.fake_ip_ready ? &dns_state.fake_ip : NULL);
#endif
                if (cfg_ptr->device_count > 0) {
                    device_policy_free(&device_state);
                    device_policy_init(&device_state, cfg_ptr);
                    if (cfg_ptr->lan_interface[0])
                        device_policy_apply(&device_state, cfg_ptr->lan_interface);
                }
                rules_engine_free(&re_state);
                proxy_group_free(&pgm_state);
                proxy_provider_free(&ppm_state);
                rule_provider_free(&rpm_state);
                /* P2: providers ДО groups при reload */
                rule_provider_init(&rpm_state, cfg_ptr);
                rule_provider_load_all(&rpm_state);
                proxy_provider_init(&ppm_state, cfg_ptr);
                proxy_provider_load_all(&ppm_state);
                /* SIGHUP reload: first_start=false → без HC stagger */
                proxy_group_init(&pgm_state, cfg_ptr, false);
                /* Pre-warm DNS после reload — провайдеры могли подгрузить
                 * новые серверы с новыми hostnames. */
                dispatcher_prewarm_resolve(&pgm_state, cfg_ptr);
                /* Geo hot-reload: пропустить если файлы не изменились.
                   При изменении — атомарный swap: load_new → free_old → swap. */
                {
                    if (geo_state.count > 0 && !geo_files_changed(&geo_state)) {
                        log_msg(LOG_DEBUG,
                            "Geo: файлы не изменились, hot-reload пропущен");
                    } else {
                        geo_manager_t new_geo;
                        memset(&new_geo, 0, sizeof(new_geo));
                        if (geo_manager_init(&new_geo, cfg_ptr) == 0) {
                            geo_load_region_categories(&new_geo, cfg_ptr);
                            if (new_geo.count > 0) {
                                uint32_t prev_rc = geo_state.reload_count;
                                geo_manager_free(&geo_state);
                                geo_state = new_geo;
                                geo_state.last_reload_time = time(NULL);
                                geo_state.reload_count     = prev_rc + 1;
                                geo_state.last_reload_ok   = true;
                                http_server_set_geo_manager(&geo_state);
                                log_msg(LOG_INFO,
                                    "Geo hot-reload #%u: %d категорий",
                                    geo_state.reload_count, geo_state.count);
                                {
                                    static char ev_geo[128];
                                    snprintf(ev_geo, sizeof(ev_geo),
                                        "{\"type\":\"geo_reloaded\",\"categories\":%d,\"count\":%u}",
                                        geo_state.count, geo_state.reload_count);
                                    http_server_emit_event(ev_geo);
                                }
                            } else {
                                log_msg(LOG_WARN,
                                    "Geo: ни одна категория не загружена — сохраняем старые данные");
                                geo_manager_free(&new_geo);
                                geo_state.last_reload_ok = false;
                            }
                        } else {
                            log_msg(LOG_WARN,
                                "Geo: ошибка hot-reload — оставляем старые данные");
                            geo_manager_free(&new_geo);
                            geo_state.last_reload_ok = false;
                        }
                    }
                }
                rules_engine_init(&re_state, cfg_ptr, &pgm_state, &rpm_state,
                                  &geo_state);
                dispatcher_set_rules_engine(&re_state);
                dispatcher_set_pgm(&pgm_state);
                http_server_set_re(&re_state);
                ipc_set_3x_context(&pgm_state, &rpm_state, &re_state,
                                   &geo_state);
                /* 3.5.1: перепривязать geo_manager после reload */
                dns_rules_set_geo_manager(&geo_state);
                if (cfg_ptr->dns.block_geosite_ads)
                    dns_rules_add_geosite(GEO_CAT_ADS,      DNS_ACTION_BLOCK);
                if (cfg_ptr->dns.block_geosite_trackers)
                    dns_rules_add_geosite(GEO_CAT_TRACKERS,  DNS_ACTION_BLOCK);
                if (cfg_ptr->dns.block_geosite_threats)
                    dns_rules_add_geosite(GEO_CAT_THREATS,   DNS_ACTION_BLOCK);
                /* 3.5.5: перепривязать rules_engine после reload */
                dns_rules_set_engine(dns_engine_consult);
                /* Flow offload: переактивировать — WAN мог измениться */
                nft_flow_offload_disable();
                if (cfg_ptr->flow_offload)
                    nft_flow_offload_enable(cfg_ptr->lan_interface[0]
                                            ? cfg_ptr->lan_interface : NULL);
                /* TC fast path: переактивировать с новым конфигом */
                tc_fast_disable(cfg_ptr->lan_interface[0] ? cfg_ptr->lan_interface : "br-lan");
                if (cfg_ptr->tc_fast_enabled)
                    tc_fast_enable(cfg_ptr->lan_interface[0] ? cfg_ptr->lan_interface : "br-lan",
                                   cfg_ptr->lan_prefix, cfg_ptr->lan_mask);
                /* MTU: переприменить если изменился в конфиге */
                if (cfg_ptr->mtu > 0 && cfg_ptr->lan_interface[0]) {
                    static char mtu_reload_arg[8];
                    snprintf(mtu_reload_arg, sizeof(mtu_reload_arg), "%u",
                             (unsigned)cfg_ptr->mtu);
                    const char *const av[] = {"ip","link","set","dev",
                                              cfg_ptr->lan_interface,"mtu",
                                              mtu_reload_arg,NULL};
                    exec_cmd_safe(av,NULL,0);
                }
                http_server_set_config(cfg_ptr);
                http_server_set_pgm(&pgm_state);
                log_msg(LOG_INFO, "Конфигурация обновлена");
                http_server_emit_event("{\"type\":\"daemon_reload\",\"reason\":\"sighup\"}");
            } else {
                if (new_cfg_ptr) free(new_cfg_ptr);
                log_msg(LOG_ERROR, "Ошибка загрузки конфига, сохраняем текущий");
            }
#if CONFIG_EBURNET_DPI
            /* Гарантировать существование директории и сохранить кэш */
            (void)mkdir("/etc/4eburnet", 0755);
            dpi_adapt_save(&g_dpi_adapt, "/etc/4eburnet/dpi_cache.bin");
#endif
            state.reload = false;
        }

        /* Async обновление CDN IP по запросу IPC (C.6) */
#if CONFIG_EBURNET_DPI
        /* Автотик: cdn_updater_tick проверяет time(NULL) внутри, не блокирует */
        if (state.cdn_pipe_fd < 0) {
            int tfd = cdn_updater_tick(&state.cdn_next_check, cfg_ptr);
            if (tfd >= 0) {
                state.cdn_pipe_fd = tfd;
                struct epoll_event _pev = {
                    .events  = EPOLLIN | EPOLLHUP,
                    .data.fd = tfd,
                };
                epoll_ctl(master_epoll, EPOLL_CTL_ADD, tfd, &_pev);
            }
        }
        if (state.cdn_update_requested && state.cdn_pipe_fd < 0) {
            state.cdn_update_requested = false;
            log_msg(LOG_INFO, "Запуск async CDN update...");
            int cfd = cdn_updater_update_async(cfg_ptr);
            if (cfd >= 0) {
                state.cdn_pipe_fd = cfd;
                struct epoll_event pev = {
                    .events  = EPOLLIN | EPOLLHUP,
                    .data.fd = cfd,
                };
                epoll_ctl(master_epoll, EPOLL_CTL_ADD, cfd, &pev);
            } else {
                log_msg(LOG_WARN, "CDN update: fork не удался");
            }
        }
#endif
    }

cleanup:
#if CONFIG_EBURNET_DPI
    /* Гарантировать существование директории и сохранить кэш */
    (void)mkdir("/etc/4eburnet", 0755);
    dpi_adapt_save(&g_dpi_adapt, "/etc/4eburnet/dpi_cache.bin");
    if (state.cdn_pipe_fd >= 0) {
        close(state.cdn_pipe_fd);
        state.cdn_pipe_fd = -1;
    }
#endif
    http_server_close(&g_http);
    if (master_epoll >= 0) close(master_epoll);

    /* Завершение работы */
    log_msg(LOG_INFO, "Завершение работы...");
    log_flush();

    rules_engine_free(&re_state);
    geo_manager_free(&geo_state);
    proxy_provider_free(&ppm_state);
    rule_provider_free(&rpm_state);
    proxy_group_free(&pgm_state);
    device_policy_free(&device_state);
    device_policy_cleanup_nft();
    if (dns_state.initialized) {
        dns_server_cleanup(&dns_state);
        dns_rules_free();
    }
    rules_cleanup(&rules_state);
    dispatcher_cleanup(&dispatcher_state);
    tproxy_cleanup(&tproxy_state);
    policy_cleanup();
    nft_flow_offload_disable();
    tc_fast_disable(cfg_ptr->lan_interface[0] ? cfg_ptr->lan_interface : "br-lan");
    nft_dnat_cleanup();
    nft_cleanup();
    ipc_cleanup(state.ipc_fd);
    tls_hc_ctx_free();
    tls_global_cleanup();
    config_free(cfg_ptr);
    free(cfg_ptr);
    unlink(EBURNET_PID_FILE);

    log_msg(LOG_INFO, "%s остановлен", EBURNET_NAME);
    log_close();

    return 0;
}
