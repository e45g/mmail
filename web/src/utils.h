#ifndef UTILS_H
#define UTILS_H

#include "server.h"
#include "json/json.h"

#include "log.h"
#include "config.h"

#define MAX_LINE_LENGTH 256

const char *get_routes_dir(void);
const char *get_public_dir(void);


char *get_header(http_req_t *request, const char *name);

int validate_http_method(const char* method);
char* sanitize_path(const char* path);
int validate_header(const char* name, const char* value);

typedef struct {
    char *key;
    char *value;
} form_field_t;

form_field_t *parse_form_data(const char *body, int *count);
char *get_form_field(form_field_t *fields, int count, const char *key);
void free_form_fields(form_field_t *fields, int count);

char *url_decode(const char *src);
char *html_escape(const char *text);

#endif
