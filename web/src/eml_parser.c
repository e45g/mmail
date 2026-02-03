#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "eml_parser.h"
#include "utils.h"

static char *read_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (size <= 0 || size > 10 * 1024 * 1024) {  // Max 10MB
        fclose(f);
        return NULL;
    }

    char *content = malloc(size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(content, 1, size, f);
    content[read] = '\0';
    fclose(f);

    return content;
}

static char *trim(char *str) {
    if (!str) return NULL;

    while (isspace((unsigned char)*str)) str++;

    if (*str == 0) return str;

    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';

    return str;
}

char *extract_header(const char *headers, const char *name) {
    if (!headers || !name) return NULL;

    size_t name_len = strlen(name);
    const char *pos = headers;

    while ((pos = strcasestr(pos, name)) != NULL) {
        if (pos != headers && *(pos - 1) != '\n') {
            pos++;
            continue;
        }

        if (*(pos + name_len) != ':') {
            pos++;
            continue;
        }

        const char *value_start = pos + name_len + 1;

        while (*value_start == ' ' || *value_start == '\t') value_start++;

        const char *value_end = value_start;
        while (*value_end) {
            if (*value_end == '\r' || *value_end == '\n') {
                // Check for continuation (line starting with whitespace)
                const char *next = value_end;
                while (*next == '\r' || *next == '\n') next++;
                if (*next == ' ' || *next == '\t') {
                    value_end = next;
                    continue;
                }
                break;
            }
            value_end++;
        }

        size_t value_len = value_end - value_start;
        char *value = malloc(value_len + 1);
        if (!value) return NULL;

        size_t j = 0;
        for (size_t i = 0; i < value_len; i++) {
            if (value_start[i] == '\r' || value_start[i] == '\n') {
                continue;
            }
            if (value_start[i] == '\t') {
                value[j++] = ' ';
            } else {
                value[j++] = value_start[i];
            }
        }
        value[j] = '\0';

        return value;
    }

    return NULL;
}

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static char *base64_decode(const char *input, size_t len) {
    size_t output_len = (len * 3) / 4;
    char *output = malloc(output_len + 1);
    if (!output) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; i += 4) {
        int a = base64_decode_char(input[i]);
        int b = (i + 1 < len) ? base64_decode_char(input[i + 1]) : 0;
        int c = (i + 2 < len) ? base64_decode_char(input[i + 2]) : 0;
        int d = (i + 3 < len) ? base64_decode_char(input[i + 3]) : 0;

        if (a < 0 || b < 0) break;

        output[j++] = (a << 2) | (b >> 4);
        if (input[i + 2] != '=' && c >= 0) {
            output[j++] = ((b & 0x0F) << 4) | (c >> 2);
            if (input[i + 3] != '=' && d >= 0) {
                output[j++] = ((c & 0x03) << 6) | d;
            }
        }
    }
    output[j] = '\0';
    return output;
}

char *decode_mime_header(const char *encoded) {
    if (!encoded) return NULL;

    if (strncmp(encoded, "=?", 2) != 0) {
        return strdup(encoded);
    }

    char *result = malloc(strlen(encoded) + 1);
    if (!result) return NULL;
    result[0] = '\0';

    const char *pos = encoded;
    size_t result_len = 0;

    while (*pos) {
        if (strncmp(pos, "=?", 2) == 0) {
            const char *charset_start = pos + 2;
            const char *charset_end = strchr(charset_start, '?');
            if (!charset_end) break;

            char encoding = *(charset_end + 1);
            if (*(charset_end + 2) != '?') break;

            const char *text_start = charset_end + 3;
            const char *text_end = strstr(text_start, "?=");
            if (!text_end) break;

            size_t text_len = text_end - text_start;
            char *text = malloc(text_len + 1);
            if (!text) break;
            memcpy(text, text_start, text_len);
            text[text_len] = '\0';

            char *decoded = NULL;
            if (encoding == 'B' || encoding == 'b') {
                decoded = base64_decode(text, text_len);
            } else if (encoding == 'Q' || encoding == 'q') {
                decoded = malloc(text_len + 1);
                if (decoded) {
                    size_t j = 0;
                    for (size_t i = 0; i < text_len; i++) {
                        if (text[i] == '_') {
                            decoded[j++] = ' ';
                        } else if (text[i] == '=' && i + 2 < text_len) {
                            char hex[3] = {text[i+1], text[i+2], '\0'};
                            decoded[j++] = (char)strtol(hex, NULL, 16);
                            i += 2;
                        } else {
                            decoded[j++] = text[i];
                        }
                    }
                    decoded[j] = '\0';
                }
            }

            free(text);

            if (decoded) {
                size_t dec_len = strlen(decoded);
                memcpy(result + result_len, decoded, dec_len);
                result_len += dec_len;
                result[result_len] = '\0';
                free(decoded);
            }

            pos = text_end + 2;
            while (*pos == ' ' || *pos == '\t') pos++;
        } else {
            result[result_len++] = *pos++;
            result[result_len] = '\0';
        }
    }

    return result;
}

parsed_email_t *parse_eml_file(const char *file_path) {
    char *content = read_file(file_path);
    if (!content) return NULL;

    parsed_email_t *email = calloc(1, sizeof(parsed_email_t));
    if (!email) {
        free(content);
        return NULL;
    }

    char *body_start = strstr(content, "\r\n\r\n");
    if (!body_start) {
        body_start = strstr(content, "\n\n");
    }

    char *headers = content;
    int has_headers = 0;

    if (body_start) {
        *body_start = '\0';
        body_start += (body_start[1] == '\n') ? 2 : 4;
        char *first_colon = strchr(headers, ':');
        char *first_newline = strchr(headers, '\n');
        if (first_colon && (!first_newline || first_colon < first_newline)) {
            has_headers = 1;
        }
    }

    if (!has_headers) {
        email->from = strdup("Unknown");
        email->to = strdup("Unknown");
        email->subject = strdup("(No subject)");
        email->date = strdup("Unknown date");
        email->content_type = NULL;
        email->body = strdup(content);
        free(content);
        return email;
    }

    char *from_raw = extract_header(headers, "From");
    char *to_raw = extract_header(headers, "To");
    char *subject_raw = extract_header(headers, "Subject");
    char *date_raw = extract_header(headers, "Date");

    email->from = from_raw ? decode_mime_header(trim(from_raw)) : strdup("Unknown");
    email->to = to_raw ? decode_mime_header(trim(to_raw)) : strdup("Unknown");
    email->subject = subject_raw ? decode_mime_header(trim(subject_raw)) : strdup("(No subject)");
    email->date = date_raw ? strdup(trim(date_raw)) : strdup("Unknown date");
    email->content_type = extract_header(headers, "Content-Type");

    if (from_raw) free(from_raw);
    if (to_raw) free(to_raw);
    if (subject_raw) free(subject_raw);
    if (date_raw) free(date_raw);

    if (body_start && *body_start) {
        email->body = strdup(body_start);
    } else {
        email->body = strdup("");
    }

    free(content);
    return email;
}

void free_parsed_email(parsed_email_t *email) {
    if (!email) return;

    free(email->from);
    free(email->to);
    free(email->subject);
    free(email->date);
    free(email->content_type);
    free(email->body);
    free(email);
}
