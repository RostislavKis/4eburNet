#include "phoenix.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

/* Файловый дескриптор лога и минимальный уровень */
static FILE       *log_file     = NULL;
static log_level_t log_min_level = LOG_INFO;
static bool        g_daemon_mode  = false;

/* Строковые представления уровней */
static const char *level_names[] = {
    [LOG_DEBUG] = "DEBUG",
    [LOG_INFO]  = "INFO",
    [LOG_WARN]  = "WARN",
    [LOG_ERROR] = "ERROR",
};

/* Проверка размера лога, обрезка при превышении лимита */
static void log_check_size(void)
{
    if (!log_file)
        return;

    struct stat st;
    int fd = fileno(log_file);
    if (fstat(fd, &st) == 0 && st.st_size > PHOENIX_LOG_MAX_BYTES) {
        /* Обрезаем файл до нуля */
        if (ftruncate(fd, 0) < 0) return;
        rewind(log_file);
        fprintf(log_file, "[TRUNCATED] Лог превысил %d байт, очищен\n",
                PHOENIX_LOG_MAX_BYTES);
        fflush(log_file);
    }
}


void log_init(const char *path, log_level_t min_level)
{
    log_min_level = min_level;

    if (path) {
        /* M-06: O_CLOEXEC для лог-файла */
        int logfd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        log_file = (logfd >= 0) ? fdopen(logfd, "a") : NULL;
        if (!log_file) {
            if (logfd >= 0) close(logfd);
            fprintf(stderr, "Не удалось открыть лог-файл: %s\n", path);
        }
    }
}

void log_set_daemon_mode(bool daemon)
{
    g_daemon_mode = daemon;
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    /* M-07: bounds check для level_names[] */
    if (level < 0) level = 0;
    if (level > LOG_ERROR) level = LOG_ERROR;

    if (level < log_min_level)
        return;

    /* Формируем метку времени */
    time_t now = time(NULL);
    struct tm tm_buf;
    localtime_r(&now, &tm_buf);

    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_buf);

    const char *lvl = (level <= LOG_ERROR) ? level_names[level] : "UNKNOWN";

    /* Вывод в stderr */
    va_list ap;

    /* В daemon mode stderr = /dev/null, пропускаем бесполезный syscall */
    if (!g_daemon_mode) {
        va_start(ap, fmt);
        fprintf(stderr, "[%s] [%s] ", ts, lvl);
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }

    /* Вывод в файл, если открыт */
    if (log_file) {
        log_check_size();

        va_start(ap, fmt);
        fprintf(log_file, "[%s] [%s] ", ts, lvl);
        vfprintf(log_file, fmt, ap);
        fprintf(log_file, "\n");
        fflush(log_file);
        va_end(ap);
    }
}

void log_flush(void)
{
    if (log_file)
        fflush(log_file);
}

void log_close(void)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }
}
