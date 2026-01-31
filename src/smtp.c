#include <fcntl.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "smtp.h"

extern SSL_CTX *global_ssl_context;

inline void send_response(smtp_session_t *s, const char *msg) {
    if (s->is_tls) {
        SSL_write(s->ssl, msg, strlen(msg));
    } else {
        send(s->fd, msg, strlen(msg), 0);
    }
}

static void parse_mail(const char *cmd, char *out) {
    const char *start = strchr(cmd, '<');
    const char *end = strchr(cmd, '>');
    if(start && end) {
        strncpy(out, start+1, end - start - 1);
        out[end-start-1] = '\0';
    }
}

cmd_result_t handle_smtp_command(smtp_session_t *session, const char *cmd) {
    char lower_cmd[256];
    int cmd_len = strlen(cmd);
    strncpy(lower_cmd, cmd, cmd_len);
    lower_cmd[cmd_len] = '\0';

    for(int i = 0; lower_cmd[i] != '\0'; i++) {
        if(lower_cmd[i] >= 'A' && lower_cmd[i] <= 'Z') lower_cmd[i] += 0x20;
    }

    if(strncmp(lower_cmd, "helo", 4) == 0) {
        send_response(session, "250 e45g.org OK\r\n");
        session->state = STATE_MAIL_FROM;
    }

    else if(strncmp(lower_cmd, "ehlo", 4) == 0) {
        send_response(session, "250-e45g.org OK\r\n250 STARTTLS\r\n");
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

        return CMD_OK;
    }

    else if(strncmp(lower_cmd, "mail from", 9) == 0) {
        parse_mail(lower_cmd, session->sender);
        send_response(session, "250 OK\r\n");
        session->state = STATE_RCPT_TO;
    }

    else if(strncmp(lower_cmd, "rcpt to", 7) == 0) {
        if(session->recipient_count < MAX_REC) {
            parse_mail(lower_cmd, session->recipients[session->recipient_count++]);
            send_response(session, "250 OK\r\n");
        }
    }

    else if (strncmp(lower_cmd, "data", 4) == 0) {
        if (session->state != STATE_RCPT_TO) {
            send_response(session, "503 Error: need RCPT command\r\n");
            return CMD_OK;
        }
        send_response(session, "354 Start mail input; end with <CR><LF>.<CR><LF>\r\n");
        session->state = STATE_DATA;
    }

    else if (strncmp(lower_cmd, "rset", 4) == 0) {
        send_response(session, "250 OK\r\n");
        session->state = STATE_MAIL_FROM;
        session->recipient_count = 0;
        memset(session->sender, 0, sizeof(session->sender));
    }

    else if (strncmp(lower_cmd, "quit", 4) == 0) {
        send_response(session, "221 Bye\r\n");
        return CMD_CLOSE;
    }

    else {
        send_response(session, "500 Unknown command\r\n");
    }

    return CMD_OK;
}
