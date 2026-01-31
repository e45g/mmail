#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <fcntl.h>

#include "smtp.h"

#define PORT 2525
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

    if(session->state == STATE_DATA) {
        char buf[4096];

        if (session->is_tls) {
            r = SSL_read(session->ssl, buf, sizeof(buf) - 1);
        } else {
            r = recv(session->fd, buf, sizeof(buf) - 1, 0);
        }

        if(r > 0) {
            buf[r] = '\0';
            printf("%s\n", buf);
            //NOTE: \r\n.\r\n could possibly me sent across two packets
            if(strstr(buf, "\r\n.\r\n") != NULL || strcmp(buf, ".\r\n") == 0) {
                send_response(session, "250 OK: Message accepted for delivery\r\n");
                session->state = STATE_EHLO;
            }
        } else if (r == 0) {
            return CMD_CLOSE;
        }
    } else {
        char buf[1024];

        if (session->is_tls) {
            r = SSL_read(session->ssl, buf, sizeof(buf) - 1);
        } else {
            r = recv(session->fd, buf, sizeof(buf) - 1, 0);
        }

        if (r > 0) {
            buf[r] = '\0';
            char *line = strtok(buf, "\r\n");
            while (line) {
                printf("%s\n", line);
                cmd_result_t result = handle_smtp_command(session, line);
                if (result == CMD_CLOSE) return CMD_CLOSE;
                if(session->state == STATE_DATA) break;

                line = strtok(NULL, "\r\n");
            }
        } else if (r == 0) {
            return CMD_CLOSE;
        }
    }
    return CMD_OK;
}

int main(void) {
    init_openssl();
    int sckt = socket(AF_INET, SOCK_STREAM, 0);
    if(sckt < 0) handle_critical_err("Socket creation failed.", sckt);

    int opt = 1;
    setsockopt(sckt, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(sckt, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    const struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(PORT),
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

    printf("SMTP Server listening on port %d\n", PORT);

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == sckt) {
                int client_fd = accept(sckt, NULL, NULL);
                if (client_fd == -1) continue;

                smtp_session_t *session = malloc(sizeof(smtp_session_t));
                session->fd = client_fd;
                session->state = STATE_EHLO;
                session->recipient_count = 0;
                session->ssl = NULL;
                session->is_tls = 0;

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
                    close(session->fd);
                    free(session);
                }
            }
        }
    }
}
