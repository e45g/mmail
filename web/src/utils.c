// Web-specific utility functions
// Shared functions (logging, config) are now in lib/

#include <errno.h>
#include <stddef.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <ctype.h>

#include "utils.h"
#include "server.h"

#include <sys/stat.h>

static int dir_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

const char *get_routes_dir(void){
    const char *dir = getenv("ROUTES_DIR");
    if (dir) return dir;
    // Check if running from project root (unified) or web/ dir (standalone)
    return dir_exists("web/routes") ? "web/routes" : "./routes";
}

const char *get_public_dir(void){
    const char *dir = getenv("PUBLIC_DIR");
    if (dir) return dir;
    // Check if running from project root (unified) or web/ dir (standalone)
    return dir_exists("web/public") ? "web/public" : "./public";
}

char *get_header(http_req_t *request, const char *name) {
    for (int i = 0; i < request->headers_len; i++) {
        if (strcmp(request->headers[i].name, name) == 0) {
            return request->headers[i].value;
        }
    }
    return NULL;
}

char* sanitize_path(const char* path) {
    size_t path_len = strlen(path);

    if (!path || path_len == 0) return NULL;
    if (path_len >= MAX_PATH_LENGTH) return NULL;

    char* sanitized = malloc(path_len + 1);
    if (!sanitized) return NULL;

    const char* src = path;
    char* dst = sanitized;

    while (*src) {
        if (*src == '.') {
            if (src[1] == '.' && (src[2] == '/' || src[2] == '\0')) {
                free(sanitized);
                return NULL;
            }
            if (src[1] == '/' || src[1] == '\0') {
                src += (src[1] == '/') ? 2 : 1;
                continue;
            }
        }

        if (isalnum(*src) || *src == '-' || *src == '_' || *src == '.' || *src == '/') {
            *dst++ = *src;
        } else {
            free(sanitized);
            return NULL;
        }
        src++;
    }

    *dst = '\0';
    return sanitized;
}

int validate_http_method(const char* method) {
    if (!method) return 0;

    size_t len = strlen(method);
    if (len == 0 || len > MAX_METHOD_LENGTH) return 0;

    const char* allowed_methods[] = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"};
    const int num_methods = sizeof(allowed_methods) / sizeof(allowed_methods[0]);

    for (int i = 0; i < num_methods; i++) {
        if (strcmp(method, allowed_methods[i]) == 0) return 1;
    }
    return 0;
}

int validate_header(const char* name, const char* value) {
    if (!name || !value) return 0;

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);

    if (name_len == 0 || name_len > MAX_HEADER_LENGTH ||
        value_len > MAX_HEADER_LENGTH) return 0;

    for (size_t i = 0; i < name_len; i++) {
        char c = name[i];
        if (!isalnum(c) && c != '-' && c != '_') return 0;
    }

    const char* forbidden_headers[] = {"content-length", "transfer-encoding"};
    const int num_forbidden = sizeof(forbidden_headers) / sizeof(forbidden_headers[0]);

    for (int i = 0; i < num_forbidden; i++) {
        if (strcasecmp(name, forbidden_headers[i]) == 0) return 0;
    }

    return 1;
}

char *url_decode(const char *src) {
    if (!src) return NULL;

    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);
    if (!decoded) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < src_len; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            char hex[3] = {src[i + 1], src[i + 2], '\0'};
            char *end;
            long val = strtol(hex, &end, 16);
            if (end == hex + 2) {
                decoded[j++] = (char)val;
                i += 2;
            } else {
                decoded[j++] = src[i];
            }
        } else if (src[i] == '+') {
            decoded[j++] = ' ';
        } else {
            decoded[j++] = src[i];
        }
    }
    decoded[j] = '\0';
    return decoded;
}

form_field_t *parse_form_data(const char *body, int *count) {
    if (!body || !count) return NULL;

    *count = 0;

    int field_count = 1;
    for (const char *p = body; *p; p++) {
        if (*p == '&') field_count++;
    }

    form_field_t *fields = calloc(field_count, sizeof(form_field_t));
    if (!fields) return NULL;

    char *body_copy = strdup(body);
    if (!body_copy) {
        free(fields);
        return NULL;
    }

    char *saveptr;
    char *pair = strtok_r(body_copy, "&", &saveptr);
    int idx = 0;

    while (pair && idx < field_count) {
        char *eq = strchr(pair, '=');
        if (eq) {
            *eq = '\0';
            fields[idx].key = url_decode(pair);
            fields[idx].value = url_decode(eq + 1);
            idx++;
        }
        pair = strtok_r(NULL, "&", &saveptr);
    }

    free(body_copy);
    *count = idx;
    return fields;
}

char *get_form_field(form_field_t *fields, int count, const char *key) {
    if (!fields || !key) return NULL;

    for (int i = 0; i < count; i++) {
        if (fields[i].key && strcmp(fields[i].key, key) == 0) {
            return fields[i].value;
        }
    }
    return NULL;
}

void free_form_fields(form_field_t *fields, int count) {
    if (!fields) return;

    for (int i = 0; i < count; i++) {
        free(fields[i].key);
        free(fields[i].value);
    }
    free(fields);
}

char *html_escape(const char *text) {
    if (!text) return NULL;

    size_t len = strlen(text);
    size_t escaped_len = 0;

    for (size_t i = 0; i < len; i++) {
        switch (text[i]) {
            case '<':
            case '>': escaped_len += 4; break;
            case '&': escaped_len += 5; break;
            case '"': escaped_len += 6; break;
            default: escaped_len++; break;
        }
    }

    char *escaped = malloc(escaped_len + 1);
    if (!escaped) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        switch (text[i]) {
            case '<':
                memcpy(escaped + j, "&lt;", 4);
                j += 4;
                break;
            case '>':
                memcpy(escaped + j, "&gt;", 4);
                j += 4;
                break;
            case '&':
                memcpy(escaped + j, "&amp;", 5);
                j += 5;
                break;
            case '"':
                memcpy(escaped + j, "&quot;", 6);
                j += 6;
                break;
            default:
                escaped[j++] = text[i];
                break;
        }
    }
    escaped[j] = '\0';
    return escaped;
}
