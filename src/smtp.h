#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_REC 10

typedef enum {
    STATE_EHLO,
    STATE_MAIL_FROM,
    STATE_RCPT_TO,
    STATE_DATA,
    STATE_QUIT
} smtp_state_t;

typedef enum {
    CMD_OK,
    CMD_CLOSE
} cmd_result_t;

typedef struct {
    int fd;
    int is_tls;
    SSL *ssl;
    smtp_state_t state;
    char sender[256];
    char recipients[MAX_REC][256];
    int recipient_count;
} smtp_session_t;

cmd_result_t handle_smtp_command(smtp_session_t*, const char*);
void send_response(smtp_session_t *s, const char *msg);
