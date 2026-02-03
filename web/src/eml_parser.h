#ifndef EML_PARSER_H
#define EML_PARSER_H

typedef struct {
    char *from;
    char *to;
    char *subject;
    char *date;
    char *content_type;
    char *body;
} parsed_email_t;

parsed_email_t *parse_eml_file(const char *file_path);
void free_parsed_email(parsed_email_t *email);

char *decode_mime_header(const char *encoded);
char *extract_header(const char *headers, const char *name);

#endif
