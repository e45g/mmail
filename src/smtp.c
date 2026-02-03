#include <ctype.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"
#include "smtp.h"
#include "postgre.h"

extern SSL_CTX *global_ssl_context;

static int parse_mail(const char *cmd, char *out, size_t out_sz)
{
    const char *start = strchr(cmd, '<');
    const char *end   = strchr(cmd, '>');

    if (!start || !end || end <= start + 1)
        return -1;

    size_t len = (size_t)(end - start - 1);

    if (len == 0 || len >= out_sz)
        return -1;

    memcpy(out, start + 1, len);
    out[len] = '\0';

    const char *at = strchr(out, '@');
    if (!at || at == out || *(at + 1) == '\0')
        return -1;

    return 0;
}

int store_email(smtp_session_t *s) {
    // TOOO: Make the path configurable
    mkdir("emails", 0700);

    char file_path[256];
    snprintf(file_path, sizeof(file_path), "emails/%ld_%d.eml", time(NULL), s->fd);

    FILE *f = fopen(file_path, "w");
    if (!f) return -1;
    fwrite(s->buffer, 1, strlen(s->buffer), f);
    fclose(f);

    const char *query = "INSERT INTO emails (sender_address, file_path, size_bytes) "
                        "VALUES ($1, $2, $3) RETURNING id";
    char size_str[32];
    snprintf(size_str, sizeof(size_str), "%zu", strlen(s->buffer));

    const char *params[] = {s->sender, file_path, size_str};
    db_result_t *res = db_prepare(query, params, 3);

    if (!res || res->num_rows == 0) {
        db_free(res);
        return -1;
    }
    char *email_id = strdup(res->rows[0][0]);
    db_free(res);

    for (int i = 0; i < s->recipient_count; i++) {
        db_result_t *u_res = db_prepare("SELECT id FROM users WHERE full_address = $1",
                                       (const char*[]){s->recipients[i]}, 1);
        if (u_res && u_res->num_rows > 0) {
            const char *inbox_params[] = {u_res->rows[0][0], email_id};
            db_prepare("INSERT INTO user_inbox (user_id, email_id) VALUES ($1, $2)", inbox_params, 2);
        }
        db_free(u_res);
    }

    free(email_id);
    return 0;
}

void rcpt_to(char *cmd, smtp_session_t *session) {
    if (session->recipient_count >= MAX_RECIPIENTS) {
        send_response(session, "452 Too many recipients\r\n");
        return;
    }

    char email[MAX_EMAIL_LEN];
    if (parse_mail(cmd, email, sizeof(email)) != 0) {
        send_response(session, "501 Syntax error in RCPT TO\r\n");
        return;
    }

    char *at = strchr(email, '@');
    if (!at || at == email || *(at + 1) == '\0') {
        send_response(session, "501 Invalid email address\r\n");
        return;
    }

    size_t user_len   = at - email;
    size_t domain_len = strlen(at + 1);

    if (user_len >= MAX_USER_LEN || domain_len >= MAX_DOMAIN_LEN) {
        send_response(session, "501 Address too long\r\n");
    }

    strncpy(session->recipients[session->recipient_count], email, MAX_EMAIL_LEN - 1);
    session->recipients[session->recipient_count][MAX_EMAIL_LEN - 1] = '\0';

    db_result_t *res = db_prepare("SELECT id FROM users WHERE full_address = $1", (const char*[]){session->recipients[session->recipient_count]}, 1);
    if(res == NULL || res->num_rows <= 0) {
        send_response(session, "550 5.1.1 Not found? I hope this is not a bug in my code :)\r\n");
        db_free(res);
        return;
    }
    db_free(res);

    session->recipient_count++;
    send_response(session, "250 Recipient accepted\r\n");
}

cmd_result_t handle_smtp_command(smtp_session_t *session, const char *cmd) {
    char lower_cmd[BUFFER_SIZE]; // ehhh.... it will be enough, right?
    size_t cmd_len = strlen(cmd);
    strncpy(lower_cmd, cmd, cmd_len);
    lower_cmd[cmd_len] = '\0';

    if (cmd_len >= sizeof(lower_cmd)) cmd_len = sizeof(lower_cmd) - 1;

    for(size_t i = 0; i < cmd_len; i++) {
        lower_cmd[i] = (unsigned char)tolower((unsigned char)cmd[i]);
    }
    lower_cmd[cmd_len] = '\0';

    if(strncmp(lower_cmd, "helo", 4) == 0 || strncmp(lower_cmd, "ehlo", 4) == 0) {
        if (lower_cmd[0] == 'e') {
            send_response(session, "250-Here are commands I support, there aren't many. I know.\r\n250-STARTTLS\r\n250 RSET\r\n");
        } else {
            send_response(session, "250 Oh, look, another connection.\r\n");
        }
        session->state = STATE_MAIL_FROM;
    }

    else if(strncmp(lower_cmd, "starttls", 8) == 0) {
        send_response(session, "220 Ready to start TLS\r\n");

        session->ssl = SSL_new(global_ssl_context);
        if (!session->ssl) {
            return CMD_CLOSE;
        }
        SSL_set_fd(session->ssl, session->fd);

        int flags = fcntl(session->fd, F_GETFL, 0);
        fcntl(session->fd, F_SETFL, flags & ~O_NONBLOCK);

        if (SSL_accept(session->ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            return CMD_CLOSE;
        }

        fcntl(session->fd, F_SETFL, flags);
        session->is_tls = 1;

        session->state = STATE_EHLO;
    }

    else if(strncmp(lower_cmd, "mail from", 9) == 0) {
        char email[MAX_EMAIL_LEN];
        if (parse_mail(lower_cmd, email, sizeof(email)) != 0) {
            send_response(session, "501 Syntax error in MAIL FROM\r\n");
            return CMD_OK;
        }
        strncpy(session->sender, email, strlen(email));
        send_response(session, "250 I've seen worse addresses, I guess.\r\n");
        session->state = STATE_RCPT_TO;
    }

    else if(strncmp(lower_cmd, "rcpt to", 7) == 0) {
        rcpt_to(lower_cmd, session);
    }

    else if (strncmp(lower_cmd, "data", 4) == 0) {
        if (session->state != STATE_RCPT_TO || session->recipient_count == 0) {
            send_response(session, "503 Error: need RCPT command\r\n");
            return CMD_OK;
        }
        send_response(session, "354 Start mail input\r\n");
        session->state = STATE_DATA;
    }

    else if (strncmp(lower_cmd, "rset", 4) == 0) {
        send_response(session, "250 OK\r\n");
        session->state = STATE_MAIL_FROM;
        session->recipient_count = 0;
        memset(session->sender, 0, MAX_EMAIL_LEN);
    }

    else if (strncmp(lower_cmd, "quit", 4) == 0) {
        send_response(session, "221 Bye\r\n");
        return CMD_CLOSE;
    }

    else {
        send_response(session, "500 I have no idea what you're talking about. Maybe try a real command?\r\n");
    }

    return CMD_OK;
}
