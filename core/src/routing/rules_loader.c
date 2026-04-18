/*
 * Загрузчик правил маршрутизации из файлов
 *
 * Читает списки CIDR из файлов в /etc/4eburnet/rules/
 * и загружает в nftables verdict maps (bypass/proxy/block).
 * Поддерживает горячую перезагрузку при изменении файлов.
 */

#include "routing/rules_loader.h"
#include "routing/nftables.h"
#include "4eburnet.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/*  Вспомогательные                                                    */
/* ------------------------------------------------------------------ */

/* Имя verdict map по типу правила (IPv4) */
static const char *map_name_for_type(rules_type_t type)
{
    switch (type) {
    case RULES_BYPASS: return NFT_VMAP_BYPASS;
    case RULES_BLOCK:  return NFT_VMAP_BLOCK;
    case RULES_PROXY:  return NFT_SET_PROXY;  /* proxy — обычный set */
    }
    return NFT_VMAP_BYPASS;
}

/* mtime файла, 0 при ошибке */
static time_t file_mtime(const char *path)
{
    struct stat st;
    if (stat(path, &st) < 0)
        return 0;
    return st.st_mtime;
}

/* Создать директорию рекурсивно без fork/exec (M-05) */
static void ensure_dir(const char *path)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* ------------------------------------------------------------------ */
/*  rules_init                                                         */
/* ------------------------------------------------------------------ */

int rules_init(rules_manager_t *rm)
{
    memset(rm, 0, sizeof(*rm));
    ensure_dir(EBURNET_RULES_DIR);
    log_msg(LOG_DEBUG, "Менеджер правил инициализирован (%s)",
            EBURNET_RULES_DIR);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  rules_cleanup                                                      */
/* ------------------------------------------------------------------ */

void rules_cleanup(rules_manager_t *rm)
{
    log_msg(LOG_DEBUG, "Менеджер правил: %d источников, "
            "последнее обновление %ld",
            rm->source_count, (long)rm->last_update);
    memset(rm, 0, sizeof(*rm));
}

/* ------------------------------------------------------------------ */
/*  rules_add_source                                                   */
/* ------------------------------------------------------------------ */

int rules_add_source(rules_manager_t *rm,
                     const char *path, rules_type_t type)
{
    if (rm->source_count >= 16) {
        log_msg(LOG_WARN, "Менеджер правил: лимит источников (16)");
        return -1;
    }

    /* M-15: whitelist-валидация пути (замена strstr("..")) */
    {
        const char *p = path;
        if (!p || !p[0]) {
            log_msg(LOG_WARN, "rules_loader: пустой путь");
            return -1;
        }
        if (p[0] == '/') {
            log_msg(LOG_WARN, "rules_loader: абсолютный путь: %s", path);
            return -1;
        }
        if (strstr(p, "..")) {
            log_msg(LOG_WARN, "rules_loader: опасный путь: %s", path);
            return -1;
        }
        for (; *p; p++) {
            if (!isalnum((unsigned char)*p) &&
                *p != '_' && *p != '-' && *p != '.' && *p != '/') {
                log_msg(LOG_WARN, "rules_loader: недопустимый символ в пути: %s", path);
                return -1;
            }
        }
    }

    rules_source_t *s = &rm->sources[rm->source_count];
    snprintf(s->path, sizeof(s->path), "%s", path);
    s->type = type;
    s->mtime = 0;
    s->loaded_count = 0;
    rm->source_count++;

    log_msg(LOG_DEBUG, "Источник правил: %s (тип %d)", path, type);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  rules_load_all — загрузить все источники                           */
/* ------------------------------------------------------------------ */

int rules_load_all(rules_manager_t *rm)
{
    int errors = 0;

    for (int i = 0; i < rm->source_count; i++) {
        rules_source_t *s = &rm->sources[i];
        const char *map = map_name_for_type(s->type);

        /* Проверяем существование файла */
        time_t mt = file_mtime(s->path);
        if (mt == 0) {
            log_msg(LOG_DEBUG, "Файл %s не найден, пропускаем", s->path);
            continue;
        }

        nft_load_result_t result;

        if (s->type == RULES_PROXY) {
            /* proxy — обычный set, batch загрузка (H-06) */
            nft_result_t rc = nft_set_load_file(NFT_SET_PROXY,
                                                 s->path, &result);
            s->loaded_count = result.loaded;
            s->mtime = mt;
            if (rc != NFT_OK && result.loaded == 0)
                errors++;
        } else {
            /* bypass/block — verdict maps, batch загрузка */
            const char *vrd = (s->type == RULES_BLOCK) ? "drop" : "accept";
            nft_result_t rc = nft_vmap_load_file(map, vrd, s->path, &result);
            s->loaded_count = result.loaded;
            s->mtime = mt;

            if (rc != NFT_OK && result.loaded == 0)
                errors++;
        }
    }

    rm->last_update = time(NULL);
    return errors > 0 ? -1 : 0;
}

/* ------------------------------------------------------------------ */
/*  rules_check_update — проверить mtime и перезагрузить               */
/* ------------------------------------------------------------------ */

int rules_check_update(rules_manager_t *rm)
{
    int reloaded = 0;

    for (int i = 0; i < rm->source_count; i++) {
        rules_source_t *s = &rm->sources[i];
        time_t mt = file_mtime(s->path);

        /* Файл не существует или не изменился */
        if (mt == 0 || mt == s->mtime)
            continue;

        log_msg(LOG_INFO, "Файл %s изменён, перезагрузка...", s->path);
        const char *map = map_name_for_type(s->type);

        if (s->type == RULES_PROXY) {
            /* Очистить set и перезагрузить batch (H-06) */
            nft_set_flush(NFT_SET_PROXY);
            nft_load_result_t result;
            nft_set_load_file(NFT_SET_PROXY, s->path, &result);
            s->loaded_count = result.loaded;
        } else {
            /* Очистить vmap и перезагрузить */
            char cmd[256];
            snprintf(cmd, sizeof(cmd),
                     "flush map inet " NFT_TABLE_NAME " %s", map);
            nft_exec(cmd);

            nft_load_result_t result;
            const char *vrd = (s->type == RULES_BLOCK) ? "drop" : "accept";
            nft_vmap_load_file(map, vrd, s->path, &result);
            s->loaded_count = result.loaded;
        }

        s->mtime = mt;
        reloaded++;
    }

    if (reloaded > 0)
        rm->last_update = time(NULL);

    return reloaded;
}

/* ------------------------------------------------------------------ */
/*  rules_create_test_file — тестовые данные для VM                    */
/* ------------------------------------------------------------------ */

int rules_create_test_file(const char *path, rules_type_t type)
{
    /* Убрана из production: не создавать тестовые файлы на реальном устройстве */
    (void)path; (void)type;
    log_msg(LOG_ERROR, "rules_create_test_file() вызвана в production — баг");
    return -1;
}
