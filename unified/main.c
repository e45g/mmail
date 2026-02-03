#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "db.h"
#include "log.h"

extern int mail_run(void);
extern void server_run(void (*load_routes)());
extern void load_routes(void);

extern SSL_CTX *global_ssl_context;

static void print_usage(const char *prog) {
    printf("mmail - Unified mail server\n\n");
    printf("Usage: %s <mode>\n\n", prog);
    printf("Modes:\n");
    printf("  --smtp    Start SMTP server (default port 25)\n");
    printf("  --web     Start Web server (default port 3000)\n");
    printf("  --help    Show this help\n");
}

static int run_smtp(void) {
    printf("Starting SMTP server...\n");
    mail_run();
    return 0;
}

static int run_web(void) {
    printf("Starting Web server...\n");
    server_run(load_routes);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    int result = load_env(".env");
    if (result != 0) {
        LOG("Invalid env file.");
    }

    const char *db_password = get_db_password();
    if (db_init("localhost", "mmail", "mmail_user", db_password) != 0) {
        LOG("Failed to init postgresql");
        return 1;
    }

    int ret = 0;

    if (strcmp(argv[1], "--smtp") == 0) {
        set_log_file("smtp");
        ret = run_smtp();
    } else if (strcmp(argv[1], "--web") == 0) {
        set_log_file("web");
        ret = run_web();
    } else if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_usage(argv[0]);
    } else {
        fprintf(stderr, "Unknown option: %s\n", argv[1]);
        print_usage(argv[0]);
        ret = 1;
    }

    db_close();

    if (global_ssl_context) {
        SSL_CTX_free(global_ssl_context);
        EVP_cleanup();
        CRYPTO_cleanup_all_ex_data();
        ERR_free_strings();
    }

    return ret;
}
