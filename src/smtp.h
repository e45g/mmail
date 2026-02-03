#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_RECIPIENTS 10
#define MAX_EMAIL_LEN 512
#define MAX_USER_LEN 256
#define MAX_DOMAIN_LEN 256

#define BUFFER_SIZE 1024*1024

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

    char buffer[BUFFER_SIZE];
    int buffer_offset;

    char sender[MAX_EMAIL_LEN];
    char recipients[MAX_RECIPIENTS][MAX_EMAIL_LEN];
    int recipient_count;
} smtp_session_t;

cmd_result_t handle_smtp_command(smtp_session_t*, const char*);
int store_email(smtp_session_t *s);
int mail_run();

