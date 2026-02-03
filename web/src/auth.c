#define _XOPEN_SOURCE 700
#include <crypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "auth.h"
#include "db.h"
#include "utils.h"

static void generate_salt(char *salt, size_t len) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    unsigned char random_bytes[32];

    if (getrandom(random_bytes, len, 0) < 0) {
        srand(time(NULL) ^ getpid());
        for (size_t i = 0; i < len; i++) {
            random_bytes[i] = rand() % 64;
        }
    }

    for (size_t i = 0; i < len; i++) {
        salt[i] = chars[random_bytes[i] % 64];
    }
    salt[len] = '\0';
}

static void generate_token(char *token) {
    const char *chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    unsigned char random_bytes[SESSION_TOKEN_LEN];

    if (getrandom(random_bytes, SESSION_TOKEN_LEN, 0) < 0) {
        srand(time(NULL) ^ getpid());
        for (int i = 0; i < SESSION_TOKEN_LEN; i++) {
            random_bytes[i] = rand() % 62;
        }
    }

    for (int i = 0; i < SESSION_TOKEN_LEN; i++) {
        token[i] = chars[random_bytes[i] % 62];
    }
    token[SESSION_TOKEN_LEN] = '\0';
}

char *hash_password(const char *password) {
    char salt[20];
    strcpy(salt, "$6$");  // SHA-512 prefix
    generate_salt(salt + 3, 16);

    char *hash = crypt(password, salt);
    if (!hash) return NULL;

    return strdup(hash);
}

int verify_password(const char *password, const char *hash) {
    if (!password || !hash) return 0;

    char *result = crypt(password, hash);
    if (!result) return 0;

    return strcmp(result, hash) == 0;
}

char *create_session(const char *user_id) {
    char *token = malloc(SESSION_TOKEN_LEN + 1);
    if (!token) return NULL;

    generate_token(token);

    const char *query =
        "INSERT INTO sessions (user_id, token, expires_at) "
        "VALUES ($1, $2, NOW() + INTERVAL '24 hours') "
        "RETURNING token";

    const char *params[] = {user_id, token};
    db_result_t *res = db_prepare(query, params, 2);

    if (!res || res->num_rows == 0) {
        free(token);
        if (res) db_free(res);
        return NULL;
    }

    db_free(res);
    return token;
}

char *get_cookie(http_req_t *req, const char *name) {
    char *cookie_header = get_header(req, "Cookie");
    if (!cookie_header) return NULL;

    size_t name_len = strlen(name);
    char *pos = cookie_header;

    while ((pos = strstr(pos, name)) != NULL) {
        // check if its the start of the string or preceded by space/semicolon
        if (pos != cookie_header && *(pos - 1) != ' ' && *(pos - 1) != ';') {
            pos++;
            continue;
        }

        // check if followed by '='
        if (*(pos + name_len) != '=') {
            pos++;
            continue;
        }

        // found
        char *value_start = pos + name_len + 1;
        char *value_end = strchr(value_start, ';');

        size_t value_len = value_end ? (size_t)(value_end - value_start) : strlen(value_start);

        char *value = malloc(value_len + 1);
        if (!value) return NULL;

        strncpy(value, value_start, value_len);
        value[value_len] = '\0';

        while (value_len > 0 && value[value_len - 1] == ' ') {
            value[--value_len] = '\0';
        }

        return value;
    }

    return NULL;
}

session_user_t *get_session_user(http_req_t *req) {
    char *token = get_cookie(req, "session");
    if (!token) return NULL;

    const char *query =
        "SELECT u.id, u.username, u.domain, u.full_address "
        "FROM sessions s "
        "JOIN users u ON s.user_id = u.id "
        "WHERE s.token = $1 AND s.expires_at > NOW()";

    const char *params[] = {token};
    db_result_t *res = db_prepare(query, params, 1);
    free(token);

    if (!res || res->num_rows == 0) {
        if (res) db_free(res);
        return NULL;
    }

    session_user_t *user = malloc(sizeof(session_user_t));
    if (!user) {
        db_free(res);
        return NULL;
    }

    strncpy(user->user_id, res->rows[0][0], sizeof(user->user_id) - 1);
    strncpy(user->username, res->rows[0][1], sizeof(user->username) - 1);
    strncpy(user->domain, res->rows[0][2], sizeof(user->domain) - 1);
    strncpy(user->full_address, res->rows[0][3], sizeof(user->full_address) - 1);

    user->user_id[sizeof(user->user_id) - 1] = '\0';
    user->username[sizeof(user->username) - 1] = '\0';
    user->domain[sizeof(user->domain) - 1] = '\0';
    user->full_address[sizeof(user->full_address) - 1] = '\0';

    db_free(res);
    return user;
}

int delete_session(const char *token) {
    const char *query = "DELETE FROM sessions WHERE token = $1";
    const char *params[] = {token};
    db_result_t *res = db_prepare(query, params, 1);

    if (res) {
        db_free(res);
        return 0;
    }
    return -1;
}

void cleanup_expired_sessions(void) {
    db_exec("DELETE FROM sessions WHERE expires_at < NOW()");
}

void send_redirect(int client_fd, const char *location) {
    char response[2048];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n",
        location);

    send(client_fd, response, len, MSG_NOSIGNAL);
}

void send_redirect_with_cookie(int client_fd, const char *location, const char *cookie) {
    char response[2048];
    int len = snprintf(response, sizeof(response),
        "HTTP/1.1 302 Found\r\n"
        "Location: %s\r\n"
        "Set-Cookie: %s\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n",
        location, cookie);

    send(client_fd, response, len, MSG_NOSIGNAL);
}

void send_html_with_cookie(int client_fd, const char *html, const char *cookie) {
    size_t html_len = strlen(html);
    size_t response_size = html_len + 1024;
    char *response = malloc(response_size);
    if (!response) return;

    int header_len = snprintf(response, response_size,
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Content-Length: %zu\r\n"
        "Set-Cookie: %s\r\n"
        "Connection: close\r\n\r\n",
        html_len, cookie);

    memcpy(response + header_len, html, html_len);

    ssize_t total = header_len + html_len;
    ssize_t sent = 0;
    while (sent < total) {
        ssize_t s = send(client_fd, response + sent, total - sent, MSG_NOSIGNAL);
        if (s <= 0) break;
        sent += s;
    }

    free(response);
}

int create_user(const char *username, const char *domain, const char *password) {
    char *password_hash = hash_password(password);
    if (!password_hash) return -1;

    const char *query =
        "INSERT INTO users (username, domain, password_hash) "
        "VALUES ($1, $2, $3) "
        "ON CONFLICT DO NOTHING "
        "RETURNING id";

    const char *params[] = {username, domain, password_hash};
    db_result_t *res = db_prepare(query, params, 3);
    free(password_hash);

    if (!res) return -1;

    int success = res->num_rows > 0 ? 0 : -1;
    db_free(res);
    return success;
}

session_user_t *authenticate_user(const char *full_address, const char *password) {
    const char *query =
        "SELECT id, username, domain, full_address, password_hash "
        "FROM users WHERE full_address = $1";

    const char *params[] = {full_address};
    db_result_t *res = db_prepare(query, params, 1);

    if (!res || res->num_rows == 0) {
        if (res) db_free(res);
        return NULL;
    }

    const char *stored_hash = res->rows[0][4];
    if (!verify_password(password, stored_hash)) {
        db_free(res);
        return NULL;
    }

    session_user_t *user = malloc(sizeof(session_user_t));
    if (!user) {
        db_free(res);
        return NULL;
    }

    strncpy(user->user_id, res->rows[0][0], sizeof(user->user_id) - 1);
    strncpy(user->username, res->rows[0][1], sizeof(user->username) - 1);
    strncpy(user->domain, res->rows[0][2], sizeof(user->domain) - 1);
    strncpy(user->full_address, res->rows[0][3], sizeof(user->full_address) - 1);

    user->user_id[sizeof(user->user_id) - 1] = '\0';
    user->username[sizeof(user->username) - 1] = '\0';
    user->domain[sizeof(user->domain) - 1] = '\0';
    user->full_address[sizeof(user->full_address) - 1] = '\0';

    db_free(res);
    return user;
}
