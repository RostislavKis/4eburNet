#include "4eburnet.h"
#include "resource_manager.h"
#include "device.h"
#include "config.h"
#include "ipc.h"
#include "routing/nftables.h"
#include "routing/policy.h"
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
#include "dpi/dpi_filter.h"
#endif

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
static rules_engine_t re_state;
static geo_manager_t geo_state;

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
        snprintf(path, sizeof(path), "%s/geoip-%s.lst", geo_dir, rl);
        geo_load_category(gm, cat_name, gm->current_region, path);

        snprintf(cat_name, sizeof(cat_name), "geosite-%s", rl);
        snprintf(path, sizeof(path), "%s/geosite-%s.lst", geo_dir, rl);
        geo_load_category(gm, cat_name, gm->current_region, path);
    }

    /* Антиреклама — если файл существует */
    snprintf(path, sizeof(path), "%s/geosite-ads.lst", geo_dir);
    geo_load_category(gm, "ads", GEO_REGION_UNKNOWN, path);
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
        /* Проверяем, жив ли процесс */
        if (kill(pid, 0) == 0) {
            fclose(f);
            return pid;  /* процесс жив */
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

    char *buf = malloc(4096);
    if (!buf) { fprintf(stderr, "{\"error\":\"OOM\"}\n"); return 1; }
    if (ipc_send_command(ipc_cmd, buf, 4096) < 0) {
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

    /* Установка времени до инициализации TLS (DEC-019) */
    if (!ntp_time_is_valid()) {
        log_msg(LOG_INFO,
            "Системное время некорректно, запуск HTTP bootstrap...");
        ntp_bootstrap();
    }

    /* Инициализация крипто-подсистемы */
    if (tls_global_init() < 0)
        log_msg(LOG_WARN, "wolfSSL недоступен, TLS протоколы отключены");

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
            mode_rc = nft_mode_set_rules();

        if (mode_rc != NFT_OK) {
            log_msg(LOG_ERROR, "nftables: режим '%s' не применён — "
                "остановка во избежание fail-open", cfg_ptr->mode);
            nft_cleanup();
            goto cleanup;
        }
    }

    /* Verdict Maps для масштабируемой маршрутизации (DEC-017) */
    if (nft_vmap_create() != NFT_OK)
        log_msg(LOG_WARN, "nft: verdict maps не созданы");

    /* HW Offload bypass (DEC-018) */
    if (nft_offload_bypass_init() != NFT_OK)
        log_msg(LOG_WARN, "nft: offload bypass не инициализирован");

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

        rules_create_test_file(bypass_file, RULES_BYPASS);
        rules_create_test_file(proxy_file,  RULES_PROXY);

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
                                   ? cfg_ptr->dns.upstream_port : 53;
                struct sockaddr_in sa = {
                    .sin_family = AF_INET,
                    .sin_port   = htons(up_port),
                };
                if (inet_pton(AF_INET, cfg_ptr->dns.upstream_default,
                              &sa.sin_addr) == 1) {
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

    /* Per-device routing (netdev MAC map) */
    if (cfg_ptr->device_count > 0 && cfg_ptr->lan_interface[0]) {
        if (device_policy_init(&device_state, cfg_ptr) < 0)
            log_msg(LOG_WARN, "device_policy: инициализация провалилась");
        else
            device_policy_apply(&device_state, cfg_ptr->lan_interface);
    }

    /* Политика маршрутизации — ip rule и ip route
     * B3-01: при холодной загрузке WAN может не быть —
     * hotplug (40-4eburnet) восстановит ip rules при ifup */
    policy_check_conflicts();
    if (strcmp(cfg_ptr->mode, "tun") == 0) {
        if (policy_init_tun(cfg_ptr->tun_iface) != POLICY_OK)
            log_msg(LOG_WARN, "policy: tun routing не применён — "
                "hotplug восстановит при поднятии WAN");
    } else if (strcmp(cfg_ptr->mode, "direct") == 0) {
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

        /* Proxy groups + rule/proxy providers + rules engine */
        if (proxy_group_init(&pgm_state, cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "proxy_group: инициализация провалилась");
            goto cleanup;
        }
        if (rule_provider_init(&rpm_state, cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "rule_provider: инициализация провалилась");
            goto cleanup;
        }
        rule_provider_load_all(&rpm_state);
        if (proxy_provider_init(&ppm_state, cfg_ptr) < 0) {
            log_msg(LOG_ERROR, "proxy_provider: инициализация провалилась");
            goto cleanup;
        }
        proxy_provider_load_all(&ppm_state);
        if (geo_manager_init(&geo_state, cfg_ptr) == 0) {
            geo_load_region_categories(&geo_state, cfg_ptr);
            /* B5-01: предупредить при пустых geo-данных в режиме rules */
            bool any_loaded = false;
            for (int gi = 0; gi < geo_state.count; gi++)
                if (geo_state.categories[gi].loaded) { any_loaded = true; break; }
            if (!any_loaded && strcmp(cfg_ptr->mode, "rules") == 0)
                log_msg(LOG_WARN, "GeoIP: наборы данных пусты — "
                    "в режиме rules трафик может не перехватываться");
        } else {
            log_msg(LOG_WARN, "GeoIP: не удалось инициализировать");
        }
        if (rules_engine_init(&re_state, cfg_ptr, &pgm_state, &rpm_state,
                              &geo_state) < 0) {
            log_msg(LOG_ERROR, "rules_engine: инициализация провалилась");
            goto cleanup;
        }
        dispatcher_set_rules_engine(&re_state);
        ipc_set_3x_context(&pgm_state, &rpm_state, &re_state, &geo_state);
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

    if (!daemon_mode) {
        /* Без демонизации: SIGHUP = завершение (SSH disconnect) */
        sigaction(SIGHUP, &sa_shutdown, NULL);
    } else {
        /* Демон: SIGHUP = перечитка конфига */
        sigaction(SIGHUP, &sa_reload, NULL);
    }

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
    state.cdn_pipe_fd = -1;

    log_msg(LOG_INFO, "Главный цикл запущен (master epoll)");

    while (state.running) {
        /* Единственный blocking wait — 10мс таймаут */
        struct epoll_event events[EPOLL_MAX_EVENTS];
        int n = epoll_wait(master_epoll, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);

        for (int i = 0; i < n; i++) {
            /* Async DoH/DoT — epoll data.ptr, не data.fd */
            if (cfg_ptr->dns.enabled && dns_state.initialized) {
                void *ptr = events[i].data.ptr;
                if (dns_server_is_async_ptr(&dns_state, ptr)) {
                    dns_server_handle_async_event(&dns_state, ptr,
                                                  events[i].events);
                    continue;
                }
            }

            int fd = events[i].data.fd;
            if (fd == state.ipc_fd) {
                ipc_process(state.ipc_fd, &state);
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
                proxy_provider_handle_fetch(&ppm_state, fd, events[i].events);
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
                        proxy_group_handle_hc_event(&pgm_state.groups[g],
                                                    fd, events[i].events);
                        hc_done = true;
                        break;
                    }
                }
                if (!hc_done)
                    tproxy_handle_event(&tproxy_state, fd);
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

            /* Зарегистрировать новые pipe fd в master epoll */
            for (int gi = 0; gi < pgm_state.count; gi++) {
                proxy_group_state_t *gs = &pgm_state.groups[gi];
                if (gs->hc_pipe_fd >= 0 && !gs->hc_registered) {
                    struct epoll_event pev = {
                        .events  = EPOLLIN | EPOLLHUP,
                        .data.fd = gs->hc_pipe_fd,
                    };
                    epoll_ctl(master_epoll, EPOLL_CTL_ADD,
                              gs->hc_pipe_fd, &pev);
                    gs->hc_registered = true;
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
                config_free(cfg_ptr);
                free(cfg_ptr);
                cfg_ptr = new_cfg_ptr;
                state.config = cfg_ptr;
                config_dump(cfg_ptr);
                dispatcher_set_context(&dispatcher_state, cfg_ptr);
                rules_check_update(&rules_state);
                /* H-09: DNS реинициализация при reload */
                if (dns_state.initialized) {
                    if (dns_state.udp_fd >= 0)
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL,
                                  dns_state.udp_fd, NULL);
                    if (dns_state.tcp_fd >= 0)
                        epoll_ctl(master_epoll, EPOLL_CTL_DEL,
                                  dns_state.tcp_fd, NULL);
                    dns_server_cleanup(&dns_state);
                }
                dns_rules_free();
                if (cfg_ptr->dns.enabled) {
                    dns_rules_init(cfg_ptr);
                    if (dns_server_init(&dns_state, cfg_ptr) == 0)
                        dns_server_register_epoll(&dns_state, master_epoll);
                }
                /* Обновить fake-ip указатель в dispatcher после reload */
#if CONFIG_EBURNET_FAKE_IP
                dispatcher_set_fake_ip(
                    dns_state.fake_ip_ready ? &dns_state.fake_ip : NULL);
#endif
                if (cfg_ptr->device_count > 0 && cfg_ptr->lan_interface[0]) {
                    device_policy_free(&device_state);
                    device_policy_init(&device_state, cfg_ptr);
                    device_policy_apply(&device_state, cfg_ptr->lan_interface);
                }
                rules_engine_free(&re_state);
                geo_manager_free(&geo_state);
                proxy_provider_free(&ppm_state);
                rule_provider_free(&rpm_state);
                proxy_group_free(&pgm_state);
                proxy_group_init(&pgm_state, cfg_ptr);
                rule_provider_init(&rpm_state, cfg_ptr);
                rule_provider_load_all(&rpm_state);
                proxy_provider_init(&ppm_state, cfg_ptr);
                proxy_provider_load_all(&ppm_state);
                if (geo_manager_init(&geo_state, cfg_ptr) == 0)
                    geo_load_region_categories(&geo_state, cfg_ptr);
                rules_engine_init(&re_state, cfg_ptr, &pgm_state, &rpm_state,
                                  &geo_state);
                dispatcher_set_rules_engine(&re_state);
                ipc_set_3x_context(&pgm_state, &rpm_state, &re_state,
                                   &geo_state);
                log_msg(LOG_INFO, "Конфигурация обновлена");
            } else {
                if (new_cfg_ptr) free(new_cfg_ptr);
                log_msg(LOG_ERROR, "Ошибка загрузки конфига, сохраняем текущий");
            }
            state.reload = false;
        }

        /* Async обновление CDN IP по запросу IPC (C.6) */
#if CONFIG_EBURNET_DPI
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
    if (state.cdn_pipe_fd >= 0) {
        close(state.cdn_pipe_fd);
        state.cdn_pipe_fd = -1;
    }
#endif
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
    nft_cleanup();
    ipc_cleanup(state.ipc_fd);
    tls_global_cleanup();
    config_free(cfg_ptr);
    free(cfg_ptr);
    unlink(EBURNET_PID_FILE);

    log_msg(LOG_INFO, "%s остановлен", EBURNET_NAME);
    log_close();

    return 0;
}
