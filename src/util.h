#pragma once

#include "smtp.h"

void logg(long line, const char *file, const char *func, const char *format, ...);
#define LOG(format, ...) logg(__LINE__, __FILE__, __PRETTY_FUNCTION__, format, ##__VA_ARGS__)

void send_response(smtp_session_t *s, const char *msg);
ssize_t read_request(smtp_session_t *s, char *msg, int size);

int load_env(const char *path);
int get_port(void);
const char *get_db_password(void);
