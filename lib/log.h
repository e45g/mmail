#ifndef MMAIL_LOG_H
#define MMAIL_LOG_H

// Set the log file name (e.g., "smtp" -> logs/smtp.log)
// Must be called before any LOG() calls
void set_log_file(const char *name);

void mmail_log(long line, const char *file, const char *func, const char *format, ...);

#define LOG(format, ...) mmail_log(__LINE__, __FILE__, __PRETTY_FUNCTION__, format, ##__VA_ARGS__)

#endif
