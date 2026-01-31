#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "smtp.h"
#include "util.h"

#define MAX_EVENTS 10

SSL_CTX *global_ssl_context = NULL;

void handle_critical_err(const char *msg, int sckt) {
    fprintf(stderr, "%s\n", msg);
    if(sckt > 0) close(sckt);
    exit(1);
}

int set_non_blocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    const SSL_METHOD *method = TLS_server_method();
    global_ssl_context = SSL_CTX_new(method);
    if (!global_ssl_context) {
        perror("Unable to create SSL context");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_certificate_file(global_ssl_context, "cert.pem", SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(global_ssl_context, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

cmd_result_t handle_smtp_client(smtp_session_t *session) {
    ssize_t r;

    while ((r = read_request(session,
                             session->buffer + session->buffer_offset,
                             BUFFER_SIZE - session->buffer_offset - 1)
           ) > 0) {
        session->buffer_offset += r;
        session->buffer[session->buffer_offset] = '\0';

        if (session->state == STATE_DATA) {
            printf("%s\n", session->buffer);
            char *term = strstr(session->buffer, "\r\n.\r\n");
            if (term) {
                send_response(session, "250 OK Message accepted for delivery\r\n");
                session->state = STATE_EHLO;

                session->buffer_offset = 0;
                memset(session->buffer, 0, BUFFER_SIZE);
            }
            return CMD_OK;
        }

        char *line_start = session->buffer;
        char *line_end;
        while ((line_end = strstr(line_start, "\r\n")) != NULL) {
            *line_end = '\0';

            printf("C: %s\n", line_start);
            if (handle_smtp_command(session, line_start) == CMD_CLOSE) {
                return CMD_CLOSE;
            }

            line_start = line_end + 2;

            if (session->state == STATE_DATA) break;
        }

        int remaining = session->buffer_offset - (line_start - session->buffer);
        if (remaining > 0 && line_start != session->buffer) {
            memmove(session->buffer, line_start, remaining);
            session->buffer_offset = remaining;
        } else if (remaining <= 0) {
            session->buffer_offset = 0;
        }

        if (session->buffer_offset >= BUFFER_SIZE - 1) {
            send_response(session, "500 Line too long\r\n");
            return CMD_CLOSE;
        }

    }
    if (r == 0) {
        return CMD_CLOSE;
    } else if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return CMD_OK;
        }
        return CMD_CLOSE;
    }
    return CMD_OK;
}

volatile sig_atomic_t keep_running = 1;

void handle_sigint(int sig) {
    (void)sig;
    keep_running = 0;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, handle_sigint);

    load_env(".env");
    const int port = get_port();

    init_openssl();
    int sckt = socket(AF_INET, SOCK_STREAM, 0);
    if(sckt < 0) handle_critical_err("Socket creation failed.", sckt);

    int opt = 1;
    setsockopt(sckt, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sckt, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    const struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {INADDR_ANY},
        .sin_zero = {0},
    };

    int result = bind(sckt, (struct sockaddr *)&addr, sizeof(addr));
    if (result != 0) handle_critical_err("Bind failed.", sckt);

    result = listen(sckt, SOMAXCONN);
    if (result != 0) handle_critical_err("Listen failed.", sckt);

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) handle_critical_err("epoll_create1 failed", sckt);

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = sckt;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sckt, &ev) == -1) {
        handle_critical_err("epoll_ctl failed", sckt);
    }

    printf("SMTP Server listening on port %d\n", port);

    while (keep_running) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == sckt) {
                int client_fd = accept(sckt, NULL, NULL);
                if (client_fd == -1) continue;

                smtp_session_t *session = calloc(1, sizeof(smtp_session_t));
                session->fd = client_fd;
                session->state = STATE_EHLO;

                if (set_non_blocking(client_fd) == -1) {
                    close(client_fd);
                    continue;
                }

                const char *greeting = "220 e45g.org ESMTP Ready\r\n";
                ssize_t sent = send(client_fd, greeting, strlen(greeting), 0);
                if (sent == -1) {
                    free(session);
                    close(client_fd);
                    continue;
                }

                ev.events = EPOLLIN | EPOLLET;
                ev.data.ptr = session;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
                    free(session);
                    close(client_fd);
                    continue;
                }
            } else {
                smtp_session_t *session = (smtp_session_t *)events[i].data.ptr;
                cmd_result_t result = handle_smtp_client(session);

                if (result == CMD_CLOSE) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, session->fd, NULL);
                    if (session->is_tls && session->ssl) {
                        SSL_free(session->ssl);
                    }
                    close(session->fd);
                    free(session);
                }
            }
        }
    }

    SSL_CTX_free(global_ssl_context);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    OSSL_LIB_CTX_free(NULL);
}
