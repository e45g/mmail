#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

static char log_path[256] = "logs/mmail.log";

void set_log_file(const char *name) {
    mkdir("logs", 0755);
    snprintf(log_path, sizeof(log_path), "logs/%s.log", name);
}

void mmail_log(long line, const char *file, const char *func, const char *format, ...) {
    time_t raw_time;
    struct tm *time_info;
    char time_buffer[20];

    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);

    // Ensure logs directory exists
    mkdir("logs", 0755);

    FILE *log_file = fopen(log_path, "a");
    if (!log_file) {
        perror("Unable to open log file");
        return;
    }

    fprintf(log_file, "[%s] LOG: [%s:%ld %s] ", time_buffer, file, line, func);
    printf("[%s] LOG: [%s:%ld %s] ", time_buffer, file, line, func);

    va_list args;
    va_start(args, format);

    vfprintf(log_file, format, args);

    va_end(args);
    va_start(args, format);

    vprintf(format, args);

    va_end(args);

    fprintf(log_file, " : %s", strerror(errno));
    printf(" status : %s\n", strerror(errno));
    errno = 0;

    fprintf(log_file, "\n");
    printf("\n");

    fclose(log_file);
}
