#ifndef MMAIL_CONFIG_H
#define MMAIL_CONFIG_H

int load_env(const char *path);
const char *get_db_password(void);
int get_smtp_port(void);
int get_web_port(void);

#endif
