#include <openssl/ssl.h>
#include <sys/socket.h>

#include "smtp.h"
#include "util.h"

void logg(long line, const char *file, const char *func, const char *format, ...) {
    time_t raw_time;
    struct tm *time_info;
    char time_buffer[20];

    time(&raw_time);
    time_info = localtime(&raw_time);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", time_info);

    FILE *log_file = fopen("log.txt", "a");
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

    fprintf(log_file, "\n\n\n");
    printf("\n\n\n");

    fclose(log_file);
}

void send_response(smtp_session_t *s, const char *msg) {
    if (s->is_tls) {
        SSL_write(s->ssl, msg, strlen(msg));
    } else {
        send(s->fd, msg, strlen(msg), 0);
    }
}

ssize_t read_request(smtp_session_t *s, char *msg, int size) {
    if (s->is_tls) {
        return SSL_read(s->ssl, msg, size);
    } else {
        return recv(s->fd, msg, size, 0);
    }
}

int load_env(const char *path){
    FILE *f = fopen(path, "r");
    if(!f){
        LOG("Failed to open .env");
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        *(strchr(line, '\n')) = '\0';

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");

        if(key && value){
            int result = setenv(key, value, 1);
            if(result != 0) LOG("setenv failed");
        }

    }
    fclose(f);
    return 0;
}

const char *get_db_password(void) {
    const char *key = getenv("DB_PASSWORD");
    return key;
}

int get_port(void) {
    const char *port = getenv("PORT");
    return port ? strtol(port, NULL, 10) : 25;
}
