#ifndef NFTABLES_H
#define NFTABLES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Имена таблицы и цепочек */
#define NFT_TABLE_NAME      "eburnet"
#define NFT_CHAIN_PRE       "prerouting"
#define NFT_CHAIN_FWD       "forward"
#define NFT_CHAIN_OUT       "output"

/* Наборы IPv4 */
#define NFT_SET_BYPASS      "bypass_addrs"
#define NFT_SET_PROXY       "proxy_addrs"
#define NFT_SET_BLOCK       "block_addrs"

/* Наборы IPv6 */
#define NFT_SET_BYPASS6     "bypass_addrs6"
#define NFT_SET_PROXY6      "proxy_addrs6"
#define NFT_SET_BLOCK6      "block_addrs6"

/* Метки fwmark — единый источник в constants.h */
#include "constants.h"
#define NFT_MARK_PROXY      FWMARK_PROXY

/* Порт TPROXY по умолчанию */
#define NFT_TPROXY_PORT     7893

/*
 * Приоритеты цепочек:
 * firewall4 использует priority mangle (-150),
 * мы ставим -200 чтобы гарантированно обработать раньше.
 * output — route hook, с fw4 не конфликтует, оставляем -150.
 */
#define NFT_PRIO_PREROUTING -200
#define NFT_PRIO_FORWARD    -200
#define NFT_PRIO_OUTPUT     -150

/* Verdict Maps — имена (DEC-017: масштабирование 300K+ записей) */
#define NFT_VMAP_BYPASS     "bypass_map"
#define NFT_VMAP_BYPASS6    "bypass_map6"
#define NFT_VMAP_BLOCK      "block_map"
#define NFT_VMAP_BLOCK6     "block_map6"

/* HW Offload bypass (DEC-018) */
#define NFT_CHAIN_OFFLOAD   "offload_bypass"
#define NFT_PRIO_OFFLOAD    -300    /* раньше всех наших цепочек */

/* Flow offload для DIRECT трафика (v1.1-3) */
#define NFT_FLOWTABLE_NAME  "eburnet_ft"
#define NFT_CHAIN_FLOW      "flow_forward"
#define NFT_PRIO_FLOW       -1      /* до fw4 forward (priority filter=0) */


/* Максимум записей в одной атомарной загрузке batch */
#define NFT_BATCH_MAX       10000

/* Результат загрузки правил */
typedef struct {
    uint32_t loaded;    /* загружено записей */
    uint32_t skipped;   /* пропущено (дубли/ошибки) */
    uint32_t errors;    /* ошибок парсинга */
} nft_load_result_t;

/* Результат операции nft */
typedef enum {
    NFT_OK           = 0,   /* успех */
    NFT_ERR_EXEC     = 1,   /* ошибка запуска nft */
    NFT_ERR_RULE     = 2,   /* ошибка применения правила */
    NFT_ERR_EXISTS   = 3,   /* уже существует */
    NFT_ERR_NOTFOUND = 4,   /* не найдено */
} nft_result_t;

/* Протоколы для правил маршрутизации */
typedef enum {
    NFT_PROTO_TCP = 0,
    NFT_PROTO_UDP = 1,
    NFT_PROTO_ALL = 2,
} nft_proto_t;

/* --- Жизненный цикл --- */

/* Создаёт таблицу inet 4eburnet с цепочками и наборами */
nft_result_t nft_init(void);

/* Удаляет таблицу inet 4eburnet (при остановке демона) */
void nft_cleanup(void);

/* Проверяет, существует ли наша таблица */
bool nft_table_exists(void);

/* --- Управление наборами IP-адресов --- */

nft_result_t nft_set_add_addr(const char *set_name, const char *cidr);
nft_result_t nft_set_del_addr(const char *set_name, const char *cidr);
nft_result_t nft_set_flush(const char *set_name);

/* --- Режимы маршрутизации --- */

/* Трафик по правилам: bypass/proxy наборы, остальное напрямую.
 * fake_ip_range — CIDR пула fake-IP из конфига; NULL = "198.51.100.0/24" */
nft_result_t nft_mode_set_rules(const char *fake_ip_range);

/* Весь трафик через TPROXY кроме bypass */
nft_result_t nft_mode_set_global(void);

/* Весь трафик напрямую (цепочки пустые) */
nft_result_t nft_mode_set_direct(void);

/* --- TPROXY --- */

nft_result_t nft_tproxy_enable(uint16_t port, nft_proto_t proto);
nft_result_t nft_tproxy_disable(void);

/* --- Verdict Maps (DEC-017) --- */

/* Создать все verdict maps в таблице 4eburnet */
nft_result_t nft_vmap_create(void);

/* Очистить все verdict maps */
nft_result_t nft_vmap_flush_all(void);

/* Batch загрузка массива CIDR строк в verdict map.
 * verdict: "accept" (bypass) или "drop" (block) */
nft_result_t nft_vmap_load_batch(const char *map_name,
                                 const char *verdict,
                                 const char **cidrs, size_t count,
                                 nft_load_result_t *result);

/* Загрузка из файла (один CIDR на строку, # комментарии).
 * verdict: "accept" (bypass) или "drop" (block) */
nft_result_t nft_vmap_load_file(const char *map_name,
                                const char *verdict,
                                const char *filepath,
                                nft_load_result_t *result);

/* Статистика verdict maps — вывод в лог */
void nft_vmap_stats(void);

/* Batch загрузка из файла в обычный set (не vmap) */
nft_result_t nft_set_load_file(const char *set_name,
                               const char *filepath,
                               nft_load_result_t *result);

/* --- HW Offload bypass (DEC-018) --- */

nft_result_t nft_offload_bypass_init(void);

/* --- Flow offload для DIRECT трафика (v1.1-3) --- */

int  nft_flow_offload_enable(void);
void nft_flow_offload_disable(void);
bool nft_flow_offload_is_active(void);

/* --- Вспомогательные --- */

/* Выполнить произвольную nft команду */
nft_result_t nft_exec(const char *cmd);

/* Текстовое описание ошибки */
const char *nft_strerror(nft_result_t err);

#endif /* NFTABLES_H */
