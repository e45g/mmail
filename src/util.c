#include <openssl/ssl.h>
#include <sys/socket.h>
#include <string.h>

#include "smtp.h"
#include "util.h"

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
