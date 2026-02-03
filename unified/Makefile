BUILD_DIR ?= ../build
OBJ_DIR = $(BUILD_DIR)/obj/unified
BIN_DIR = $(BUILD_DIR)/bin
LIB_BUILD_DIR = $(BUILD_DIR)/lib

CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra

# Use pkg-config for portable library detection
PKG_CONFIG ?= pkg-config
PQ_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpq 2>/dev/null)
PQ_LIBS := $(shell $(PKG_CONFIG) --libs libpq 2>/dev/null || echo "-lpq")
SSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
SSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

CFLAGS = $(BASE_CFLAGS) $(PQ_CFLAGS) $(SSL_CFLAGS) -I../lib -I../src -I../web/src -DUNIFIED_BUILD

SMTP_DIR = ../src
WEB_DIR = ../web/src

SMTP_SRCS = $(SMTP_DIR)/mail.c $(SMTP_DIR)/smtp.c $(SMTP_DIR)/util.c

WEB_SRCS = $(filter-out $(WEB_DIR)/postgre.c, $(wildcard $(WEB_DIR)/*.c)) $(wildcard $(WEB_DIR)/cxc/*.c)

UNIFIED_SRCS = main.c

ALL_SRCS = $(UNIFIED_SRCS) $(SMTP_SRCS) $(WEB_SRCS)

TARGET = $(BIN_DIR)/mmail

LDFLAGS = -L$(LIB_BUILD_DIR) -lmmail $(PQ_LIBS) $(SSL_LIBS) -lcrypt

.PHONY: all dirs clean

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(TARGET): $(ALL_SRCS) | dirs
	$(CC) $(CFLAGS) -o $@ $(ALL_SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)
