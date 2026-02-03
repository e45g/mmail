#include "config.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int load_env(const char *path) {
    FILE *f = fopen(path, "r");
    if(!f) {
        LOG("Failed to open .env");
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *newline = strchr(line, '\n');
        if (newline) *newline = '\0';

        char *key = strtok(line, "=");
        char *value = strtok(NULL, "=");

        if(key && value) {
            int result = setenv(key, value, 1);
            if(result != 0) LOG("setenv failed");
        }
    }
    fclose(f);
    return 0;
}

const char *get_db_password(void) {
    return getenv("DB_PASSWORD");
}

int get_smtp_port(void) {
    const char *port = getenv("SMTP_PORT");
    return port ? strtol(port, NULL, 10) : 25;
}

int get_web_port(void) {
    const char *port = getenv("WEB_PORT");
    return port ? strtol(port, NULL, 10) : 3000;
}

const char *get_web_subdomain(void) {
    const char *sub = getenv("WEB_SUBDOMAIN");
    // Return NULL if empty or not set
    if (!sub || sub[0] == '\0') return NULL;
    return sub;
}
