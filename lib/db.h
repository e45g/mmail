#ifndef MMAIL_DB_H
#define MMAIL_DB_H

#define MAX_ERROR_LEN 256
#define MAX_QUERY_LEN 4096

typedef struct {
    char ***rows;
    char **col_names;
    int num_rows;
    int num_cols;
} db_result_t;

int db_init(const char *host, const char *dbname, const char *user, const char *password);
void db_close(void);

db_result_t *db_exec(const char *query);
db_result_t *db_prepare(const char *query, const char **params, int param_count);
void db_free(db_result_t *result);

#endif
