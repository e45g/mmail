#pragma once

#include "smtp.h"

#include "log.h"
#include "config.h"

void send_response(smtp_session_t *s, const char *msg);
ssize_t read_request(smtp_session_t *s, char *msg, int size);
