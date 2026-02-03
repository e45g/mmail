#ifndef AUTH_H
#define AUTH_H

#include "server.h"
#include "db.h"

#define SESSION_TOKEN_LEN 64
#define SESSION_EXPIRY_SECONDS (24 * 60 * 60)  // 24 hours

typedef struct {
    char user_id[37];       // UUID string
    char username[256];
    char domain[256];
    char full_address[512];
} session_user_t;

char *hash_password(const char *password);
int verify_password(const char *password, const char *hash);

char *create_session(const char *user_id);
session_user_t *get_session_user(http_req_t *req);
int delete_session(const char *token);
void cleanup_expired_sessions(void);

char *get_cookie(http_req_t *req, const char *name);

void send_redirect(int client_fd, const char *location);
void send_redirect_with_cookie(int client_fd, const char *location, const char *cookie);
void send_html_with_cookie(int client_fd, const char *html, const char *cookie);

int create_user(const char *username, const char *domain, const char *password);
session_user_t *authenticate_user(const char *full_address, const char *password);

#endif
