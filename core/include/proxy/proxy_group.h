#ifndef PROXY_GROUP_H
#define PROXY_GROUP_H

#include "config.h"
#include <time.h>
#include <stdint.h>
#include <stdbool.h>
#include <arpa/inet.h>   /* INET6_ADDRSTRLEN для resolve cache (DEC-031) */

/* WHY 256: provider PrivateVPN отдаёт 102 сервера, после filter в группу попадает
 * 70-90. Лимит 32 обрезает ~50 серверов — несоответствие с mihomo (там лимита нет).
 * group_server_state_t ≈ 80 B → 256 × 80 = 20 KB на группу. 8 групп = 160 KB. */
#define PROXY_GROUP_MAX_SERVERS 256

/* WHY: mihomo использует errgroup с лимитом 10 параллельных goroutine.
 * В C — аналог: массив слотов fork'd children с pipe fd.
 * 8 слотов: 94 серверов / 8 = 12 batch × ~2s = ~24s цикл
 * против текущих 94 × 30s = ~47 минут. */
#define PROXY_GROUP_HC_SLOTS 8

/* Fallback лимит HC если /proc/meminfo недоступен. */
#define PROXY_GROUP_GLOBAL_HC_LIMIT_DEFAULT 4

typedef struct {
    int    pipe_fd;     /* read-end pipe от child; -1 = свободен */
    int    server_idx;  /* позиция в gs->servers[] (не cfg->servers[]) */
    bool   registered;  /* pipe_fd добавлен в master epoll */
    time_t spawn_time;  /* когда слот занят — для экспирации зависших дольше 25с */
} hc_slot_t;

typedef struct {
    int      server_idx;
    bool     available;
    uint32_t latency_ms;
    uint32_t fail_count;
    time_t   last_check;
    /* DEC-031: resolve cache (mutable runtime, per-server-per-group).
     * Owner: group_server_state_t. Updated by dispatcher_resolve_server().
     * resolved_family == 0  → cache empty (zero-init эквивалент "не резолвили").
     * resolved_until == 0   → never resolved; else expire = time(NULL) + resolve_ttl.
     * Проверка валидности: family != 0 && resolved_until > time(NULL). */
    char     resolved_ip[INET6_ADDRSTRLEN];
    int      resolved_family;
    time_t   resolved_until;
} group_server_state_t;

typedef struct {
    char                  name[64];
    proxy_group_type_t    type;
    group_server_state_t  servers[PROXY_GROUP_MAX_SERVERS];
    int                   server_count;
    int                   selected_idx;
    bool                  pinned;         /* ручной выбор через PUT — не сбрасывать HC */
    int                   rr_idx;
    int                   check_cursor;   /* H-1: позиция для неблокирующего health-check */
    time_t                next_check;
    char                  test_url[512];
    int                   timeout_ms;
    int                   tolerance_ms;
    int                   interval;
    /* Async health-check: параллельные слоты (аналог mihomo errgroup limit=8) */
    hc_slot_t             hc_slots[PROXY_GROUP_HC_SLOTS];
    int                   hc_active;     /* занятых слотов сейчас */
} proxy_group_state_t;

typedef struct {
    proxy_group_state_t *groups;
    int                  count;
    const EburNetConfig *cfg;
    int                  hc_total_active;  /* суммарно активных HC children по всем группам */
    int                  hc_global_limit;  /* вычисляется при инициализации по MemAvailable */
    bool                 first_round_done; /* false → burst-лимит при первом раунде */
} proxy_group_manager_t;

/* first_start: true при старте демона, false при SIGHUP reload.
 * При first_start=true применяется HC stagger для url-test групп —
 * равномерное распределение первого HC по окну HC_STAGGER_WINDOW_SEC,
 * чтобы избежать конкуренции за PROXY_GROUP_GLOBAL_HC_LIMIT при старте. */
int  proxy_group_init(proxy_group_manager_t *pgm, const EburNetConfig *cfg,
                      bool first_start);
void proxy_group_free(proxy_group_manager_t *pgm);

proxy_group_state_t *proxy_group_find(proxy_group_manager_t *pgm, const char *name);
int  proxy_group_select_server(proxy_group_manager_t *pgm, const char *group_name);
void proxy_group_update_result(proxy_group_manager_t *pgm,
                               const char *group_name,
                               int server_idx, bool success, uint32_t latency_ms);
void proxy_group_tick(proxy_group_manager_t *pgm);
int  proxy_group_to_json(const proxy_group_manager_t *pgm, char *buf, size_t buflen);
int  proxy_group_select_manual(proxy_group_manager_t *pgm,
                               const char *group_name, int server_idx);

/* Зафиксировать сбой сервера во всех SELECT-группах где он выбран.
 * После PROXY_GROUP_FAIL_THRESHOLD сбоев — переключает selected_idx. */
void proxy_group_mark_server_fail(proxy_group_manager_t *pgm, int server_idx);
/* Немедленно исключить сервер: fail_count=THRESHOLD, available=false,
 * failover selected_idx без ожидания накопления счётчика.
 * Используется в relay_try_retry при HS fail — один сбой = выброс. */
void proxy_group_mark_server_fail_immediate(proxy_group_manager_t *pgm, int server_idx);
/* То же, но только в одной группе group_name — не каскадирует на остальные.
 * Используется в relay_try_retry: сбой конкретного relay не влияет на
 * failover в других группах, которые используют тот же сервер. */
void proxy_group_mark_server_fail_for_group(proxy_group_manager_t *pgm,
                                             int server_idx,
                                             const char *group_name);
/* Сбросить счётчик сбоев сервера после успешного HS (Reality/VLESS). */
void proxy_group_mark_server_ok(proxy_group_manager_t *pgm, int server_idx);

/* Имя текущего выбранного сервера группы (по selected_idx + cfg).
 * Возвращает "" если gs NULL или server_count == 0. */
const char *proxy_group_get_current(const proxy_group_state_t *gs,
                                    const EburNetConfig *cfg);

/* Обработать результат async health-check (вызывать из epoll loop).
 * pgm нужен для декремента глобального счётчика hc_total_active.
 * cfg нужен для логирования имени сервера при url-test автовыборе. */
void proxy_group_handle_hc_event(proxy_group_manager_t *pgm,
                                  proxy_group_state_t *gs,
                                  int fd, uint32_t events,
                                  const EburNetConfig *cfg);
/* Проверить принадлежность fd к health-check группы */
bool proxy_group_owns_fd(const proxy_group_state_t *gs, int fd);

/* Сохранить selected_idx всех SELECT-групп в /etc/4eburnet/selected.json.
 * Вызывать после каждого ручного переключения сервера (PUT /proxies/{group}). */
void proxy_group_save_all_selections(const proxy_group_manager_t *pgm,
                                      const EburNetConfig *cfg);

/* Повторно применить persistent выбор для SELECT-групп с selected_idx==0.
 * Вызывать после успешного async retry провайдера — группы могут оставаться
 * на дефолтном idx=0, если провайдер не загрузился при первоначальном старте.
 * Идемпотентна: пропускает группы у которых selected_idx > 0 (уже выбран). */
void proxy_group_restore_all_selections(proxy_group_manager_t *pgm);

#endif
