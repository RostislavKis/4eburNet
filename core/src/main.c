#include "phoenix.h"
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
#include "proxy/rules_engine.h"
#include "geo/geo_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

/* Параметры master epoll */
#define EPOLL_MAX_EVENTS  32
#define EPOLL_TIMEOUT_MS  10

/* Глобальное состояние — доступно из обработчиков сигналов */
static PhoenixState state;
static tproxy_state_t tproxy_state;
static dispatcher_state_t dispatcher_state;
static rules_manager_t rules_state;
static dns_server_t dns_state;
static device_manager_t device_state;
static proxy_group_manager_t pgm_state;
static rule_provider_manager_t rpm_state;
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
                                        const PhoenixConfig *cfg)
{
    const char *geo_dir = (cfg->geo_dir[0])
        ? cfg->geo_dir : "/etc/phoenix/geo";

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
        prog, PHOENIX_CONFIG_PATH);
}

/* Проверка PID-файла — запущен ли уже демон (M-03: O_CLOEXEC) */
static pid_t check_pid_file(void)
{
    int pidfd = open(PHOENIX_PID_FILE, O_RDONLY | O_CLOEXEC);
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
    unlink(PHOENIX_PID_FILE);
    return 0;
}

/* Запись PID-файла (M-02: error handling, M-03: O_CLOEXEC) */
static void write_pid_file(void)
{
    int pidfd = open(PHOENIX_PID_FILE,
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
    ipc_command_t ipc_cmd;

    if (strcmp(cmd, "status") == 0) {
        ipc_cmd = IPC_CMD_STATUS;
    } else if (strcmp(cmd, "reload") == 0) {
        ipc_cmd = IPC_CMD_RELOAD;
    } else if (strcmp(cmd, "stop") == 0) {
        ipc_cmd = IPC_CMD_STOP;
    } else if (strcmp(cmd, "stats") == 0) {
        ipc_cmd = IPC_CMD_STATS;
    } else {
        fprintf(stderr, "Неизвестная команда: %s\n", cmd);
        return 1;
    }

    char buf[512];
    if (ipc_send_command(ipc_cmd, buf, sizeof(buf)) < 0) {
        fprintf(stderr, "Не удалось подключиться к демону. Возможно, он не запущен.\n");
        return 1;
    }

    printf("%s\n", buf);
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
    const char *config_path = PHOENIX_CONFIG_PATH;
    bool daemon_mode = false;
    int opt;

    while ((opt = getopt(argc, argv, "dc:vh")) != -1) {
        switch (opt) {
        case 'd':
            daemon_mode = true;
            break;
        case 'c':
            config_path = optarg;
            break;
        case 'v':
            printf("%s %s\n", PHOENIX_NAME, PHOENIX_VERSION);
            return 0;
        case 'h':
        default:
            print_usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    /* Проверяем, есть ли позиционная команда (status/stop/reload/stats) */
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
    log_init(PHOENIX_LOG_FILE, LOG_INFO);
    log_msg(LOG_INFO, "%s %s запускается", PHOENIX_NAME, PHOENIX_VERSION);

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
    /* TODO DEC-013: DNS_PENDING_MAX хардкожен в dns_resolver.h=64 (FULL).
       При профиле MICRO/NORMAL использует лишнюю память. Исправить в 3.6. */

    /* Настройка OOM */
    rm_apply_oom_settings();

    /* Загрузка конфигурации
     * TODO: перенести cfg на heap (malloc) для безопасности при рефакторинге.
     * Сейчас cfg живёт на стеке main() до конца — работает корректно,
     * но при будущем выносе в отдельную функцию станет use-after-free (H-12). */
    PhoenixConfig cfg;
    if (config_load(config_path, &cfg) < 0) {
        log_msg(LOG_ERROR, "Не удалось загрузить конфиг, завершение");
        tls_global_cleanup();
        log_close();
        return 1;
    }
    state.config = &cfg;

    /* Переинициализация лога с уровнем из конфига */
    log_close();
    log_init(PHOENIX_LOG_FILE, parse_log_level(cfg.log_level));

    config_dump(&cfg);

    if (!cfg.enabled) {
        log_msg(LOG_INFO, "Демон отключён в конфиге, завершение");
        tls_global_cleanup();
        config_free(&cfg);
        log_close();
        return 0;
    }

    /* Запись PID-файла */
    write_pid_file();

    /* Инициализация IPC */
    state.ipc_fd = ipc_init();
    if (state.ipc_fd < 0) {
        log_msg(LOG_ERROR, "Не удалось создать IPC сокет");
        tls_global_cleanup();
        config_free(&cfg);
        unlink(PHOENIX_PID_FILE);
        log_close();
        return 1;
    }

    /* Инициализация таблиц маршрутизации */
    if (nft_init() != NFT_OK) {
        log_msg(LOG_WARN,
            "nftables недоступен, маршрутизация отключена");
    } else {
        if (strcmp(cfg.mode, "global") == 0)
            nft_mode_set_global();
        else if (strcmp(cfg.mode, "direct") == 0)
            nft_mode_set_direct();
        else
            nft_mode_set_rules();
    }

    /* Verdict Maps для масштабируемой маршрутизации (DEC-017) */
    nft_vmap_create();

    /* HW Offload bypass (DEC-018) */
    nft_offload_bypass_init();

    /* Менеджер правил маршрутизации */
    rules_init(&rules_state);

    /* L-09: PATH_MAX на heap вместо стека */
    char *bypass_file = malloc(PATH_MAX);
    char *proxy_file = malloc(PATH_MAX);
    if (!bypass_file || !proxy_file) {
        free(bypass_file); free(proxy_file);
        log_msg(LOG_WARN, "Не удалось выделить память для путей правил");
    } else {
        int bp_n = snprintf(bypass_file, PATH_MAX,
                            "%s/bypass.cidr", PHOENIX_RULES_DIR);
        int pr_n = snprintf(proxy_file, PATH_MAX,
                            "%s/proxy.cidr", PHOENIX_RULES_DIR);
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
    if (cfg.dns.enabled) {
        dns_rules_init(&cfg);
        dns_server_init(&dns_state, &cfg);
    }

    /* Per-device routing (netdev MAC map) */
    if (cfg.device_count > 0 && cfg.lan_interface[0]) {
        device_policy_init(&device_state, &cfg);
        device_policy_apply(&device_state, cfg.lan_interface);
    }

    /* Политика маршрутизации — ip rule и ip route */
    policy_check_conflicts();
    if (strcmp(cfg.mode, "tun") == 0) {
        policy_init_tun("tun0");
    } else if (strcmp(cfg.mode, "direct") == 0) {
        /* в direct режиме правила маршрутизации не нужны */
    } else {
        /* rules и global используют TPROXY */
        policy_init_tproxy();
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
        dispatcher_set_context(&dispatcher_state, &cfg);

        /* Proxy groups + rule providers + rules engine */
        proxy_group_init(&pgm_state, &cfg);
        rule_provider_init(&rpm_state, &cfg);
        rule_provider_load_all(&rpm_state);
        if (geo_manager_init(&geo_state, &cfg) == 0)
            geo_load_region_categories(&geo_state, &cfg);
        else
            log_msg(LOG_WARN, "GeoIP: не удалось инициализировать");
        rules_engine_init(&re_state, &cfg, &pgm_state, &rpm_state,
                          &geo_state);
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

    if (!daemon_mode) {
        /* Без демонизации: SIGHUP = завершение (SSH disconnect) */
        sigaction(SIGHUP, &sa_shutdown, NULL);
    } else {
        /* Демон: SIGHUP = перечитка конфига */
        sigaction(SIGHUP, &sa_reload, NULL);
    }

    /* Master epoll: один epoll_wait вместо 3 отдельных + usleep (H-01/H-10) */
    int master_epoll = -1;
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
    if (cfg.dns.enabled && dns_state.udp_fd >= 0)
        dns_server_register_epoll(&dns_state, master_epoll);

    /* Главный цикл */
    state.running    = true;
    state.reload     = false;
    state.start_time = time(NULL);
    state.connections_total = 0;

    log_msg(LOG_INFO, "Главный цикл запущен (master epoll)");

    while (state.running) {
        /* Единственный blocking wait — 10мс таймаут */
        struct epoll_event events[EPOLL_MAX_EVENTS];
        int n = epoll_wait(master_epoll, events, EPOLL_MAX_EVENTS, EPOLL_TIMEOUT_MS);

        for (int i = 0; i < n; i++) {
            /* Async DoH/DoT — epoll data.ptr, не data.fd */
            if (cfg.dns.enabled && dns_state.initialized) {
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
            } else if (cfg.dns.enabled &&
                       dns_server_is_pending_fd(&dns_state, fd)) {
                /* Ответ от upstream DNS */
                dns_server_handle_event(&dns_state, fd, master_epoll);
            } else if (dns_state.initialized &&
                       (fd == dns_state.udp_fd || fd == dns_state.tcp_fd)) {
                dns_server_handle_event(&dns_state, fd, master_epoll);
            } else {
                tproxy_handle_event(&tproxy_state, fd);
            }
        }

        /* DNS pending таймауты — каждый тик (10ms), CLOCK_MONOTONIC дёшев (L-07) */
        if (cfg.dns.enabled && dns_state.initialized)
            dns_pending_check_timeouts(&dns_state.pending, master_epoll);

        /* Async DoH/DoT таймауты — каждые ~100мс (10 тиков × 10мс) */
        if (cfg.dns.enabled && dns_state.initialized &&
            dispatcher_state.tick_count % 10 == 0)
            dns_server_check_async_timeouts(&dns_state);

        /* Relay события в своём epoll — timeout=0, не блокирует */
        dispatcher_tick(&dispatcher_state);

        /* Периодические задачи: health-check групп и обновление провайдеров.
         * tick_count инкрементируется в dispatcher_tick, здесь проверяем
         * каждые ~30 сек (3000 тиков × 10мс) */
        if (dispatcher_state.tick_count % 3000 == 0 &&
            dispatcher_state.tick_count > 0) {
            proxy_group_tick(&pgm_state);
            rule_provider_tick(&rpm_state);
        }

        /* Перезагрузка конфига по сигналу или IPC команде */
        if (state.reload) {
            log_msg(LOG_INFO, "Перезагрузка конфигурации...");
            PhoenixConfig new_cfg;
            if (config_load(config_path, &new_cfg) == 0) {
                config_free(&cfg);
                cfg = new_cfg;
                state.config = &cfg;
                config_dump(&cfg);
                dispatcher_set_context(&dispatcher_state, &cfg);
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
                if (cfg.dns.enabled) {
                    dns_rules_init(&cfg);
                    if (dns_server_init(&dns_state, &cfg) == 0)
                        dns_server_register_epoll(&dns_state, master_epoll);
                }
                if (cfg.device_count > 0 && cfg.lan_interface[0]) {
                    device_policy_free(&device_state);
                    device_policy_init(&device_state, &cfg);
                    device_policy_apply(&device_state, cfg.lan_interface);
                }
                rules_engine_free(&re_state);
                geo_manager_free(&geo_state);
                rule_provider_free(&rpm_state);
                proxy_group_free(&pgm_state);
                proxy_group_init(&pgm_state, &cfg);
                rule_provider_init(&rpm_state, &cfg);
                rule_provider_load_all(&rpm_state);
                if (geo_manager_init(&geo_state, &cfg) == 0)
                    geo_load_region_categories(&geo_state, &cfg);
                rules_engine_init(&re_state, &cfg, &pgm_state, &rpm_state,
                                  &geo_state);
                dispatcher_set_rules_engine(&re_state);
                ipc_set_3x_context(&pgm_state, &rpm_state, &re_state,
                                   &geo_state);
                log_msg(LOG_INFO, "Конфигурация обновлена");
            } else {
                log_msg(LOG_ERROR, "Ошибка загрузки конфига, сохраняем текущий");
            }
            state.reload = false;
        }
    }

cleanup:
    if (master_epoll >= 0) close(master_epoll);

    /* Завершение работы */
    log_msg(LOG_INFO, "Завершение работы...");
    log_flush();

    rules_engine_free(&re_state);
    geo_manager_free(&geo_state);
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
    config_free(&cfg);
    unlink(PHOENIX_PID_FILE);

    log_msg(LOG_INFO, "%s остановлен", PHOENIX_NAME);
    log_close();

    return 0;
}
