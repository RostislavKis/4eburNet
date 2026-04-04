#include "phoenix.h"
#include "resource_manager.h"
#include "config.h"
#include "ipc.h"
#include "routing/nftables.h"
#include "routing/policy.h"
#include "proxy/tproxy.h"
#include "proxy/dispatcher.h"
#include "ntp_bootstrap.h"
#include "routing/rules_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

/* Глобальное состояние — доступно из обработчиков сигналов */
static PhoenixState state;
static tproxy_state_t tproxy_state;
static dispatcher_state_t dispatcher_state;
static rules_manager_t rules_state;

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

/* Проверка PID-файла — запущен ли уже демон */
static int check_pid_file(void)
{
    FILE *f = fopen(PHOENIX_PID_FILE, "r");
    if (!f)
        return 0;  /* файла нет — не запущен */

    pid_t pid = 0;
    if (fscanf(f, "%d", &pid) == 1 && pid > 0) {
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

/* Запись PID-файла */
static void write_pid_file(void)
{
    FILE *f = fopen(PHOENIX_PID_FILE, "w");
    if (f) {
        fprintf(f, "%d\n", getpid());
        fclose(f);
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

    /* Перенаправляем стандартные потоки */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    open("/dev/null", O_RDONLY);  /* stdin  */
    open("/dev/null", O_WRONLY);  /* stdout */
    open("/dev/null", O_WRONLY);  /* stderr */

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
    int existing_pid = check_pid_file();
    if (existing_pid > 0) {
        fprintf(stderr, "Демон уже запущен (PID %d)\n", existing_pid);
        return 1;
    }

    /* Демонизация, если запрошена */
    if (daemon_mode)
        daemonize();

    /* Инициализация логирования (пока с уровнем по умолчанию) */
    log_init(PHOENIX_LOG_FILE, LOG_INFO);
    log_msg(LOG_INFO, "%s %s запускается", PHOENIX_NAME, PHOENIX_VERSION);

    /* Установка времени до инициализации TLS (DEC-019) */
    if (!ntp_time_is_valid()) {
        log_msg(LOG_INFO,
            "Системное время некорректно, запуск HTTP bootstrap...");
        ntp_bootstrap();
    }

    /* Определение профиля устройства */
    state.profile = rm_detect_profile();
    log_msg(LOG_INFO, "Профиль: %s (макс. соединений: %u, буфер: %zu)",
            rm_profile_name(state.profile),
            rm_max_connections(state.profile),
            rm_buffer_size(state.profile));

    /* Настройка OOM */
    rm_apply_oom_settings();

    /* Загрузка конфигурации */
    PhoenixConfig cfg;
    if (config_load(config_path, &cfg) < 0) {
        log_msg(LOG_ERROR, "Не удалось загрузить конфиг, завершение");
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

    char bypass_file[256], proxy_file[256];
    snprintf(bypass_file, sizeof(bypass_file),
             "%s/bypass.cidr", PHOENIX_RULES_DIR);
    snprintf(proxy_file, sizeof(proxy_file),
             "%s/proxy.cidr", PHOENIX_RULES_DIR);

    rules_create_test_file(bypass_file, RULES_BYPASS);
    rules_create_test_file(proxy_file,  RULES_PROXY);

    rules_add_source(&rules_state, bypass_file, RULES_BYPASS);
    rules_add_source(&rules_state, proxy_file,  RULES_PROXY);
    rules_load_all(&rules_state);

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
    }

    /* Установка обработчиков сигналов */
    struct sigaction sa_shutdown = { .sa_handler = handle_shutdown };
    struct sigaction sa_reload   = { .sa_handler = handle_reload };
    sigemptyset(&sa_shutdown.sa_mask);
    sigemptyset(&sa_reload.sa_mask);
    sigaction(SIGTERM, &sa_shutdown, NULL);
    sigaction(SIGINT,  &sa_shutdown, NULL);

    if (!daemon_mode) {
        /* Без демонизации: SIGHUP = завершение (SSH disconnect) */
        sigaction(SIGHUP, &sa_shutdown, NULL);
    } else {
        /* Демон: SIGHUP = перечитка конфига */
        sigaction(SIGHUP, &sa_reload, NULL);
    }

    /* Главный цикл */
    state.running    = true;
    state.reload     = false;
    state.start_time = time(NULL);
    state.connections_total = 0;

    log_msg(LOG_INFO, "Главный цикл запущен");

    while (state.running) {
        /* Обработка сетевых событий (первым — приоритет) */
        tproxy_process(&tproxy_state);
        dispatcher_tick(&dispatcher_state);

        /* Обработка IPC запросов */
        ipc_process(state.ipc_fd, &state);

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
                log_msg(LOG_INFO, "Конфигурация обновлена");
            } else {
                log_msg(LOG_ERROR, "Ошибка загрузки конфига, сохраняем текущий");
            }
            state.reload = false;
        }

        /* Пауза 10мс — снижение нагрузки на CPU */
        usleep(10000);
    }

    /* Завершение работы */
    log_msg(LOG_INFO, "Завершение работы...");
    log_flush();

    rules_cleanup(&rules_state);
    dispatcher_cleanup(&dispatcher_state);
    tproxy_cleanup(&tproxy_state);
    policy_cleanup();
    nft_cleanup();
    ipc_cleanup(state.ipc_fd);
    config_free(&cfg);
    unlink(PHOENIX_PID_FILE);

    log_msg(LOG_INFO, "%s остановлен", PHOENIX_NAME);
    log_close();

    return 0;
}
