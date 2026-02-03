#include "postgre.h"
#include "smtp.h"
#include "util.h"

extern SSL_CTX *global_ssl_context;

int main(void) {
    load_env(".env");

    int r = db_init("localhost", "mmail", "mmail_user", get_db_password());
    if(r != 0) {
        LOG("Connection to postgresql failed.");
        goto clean;
    }

    mail_run();

clean:
    db_close();
    SSL_CTX_free(global_ssl_context);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    OSSL_LIB_CTX_free(NULL);
    return 0;
}
