CC = gcc
CFLAGS = -Wall -Wextra -Ilib

# Use pkg-config for portable library detection (works across distros including Raspberry Pi OS)
PKG_CONFIG ?= pkg-config

# PostgreSQL flags (libpq)
PQ_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpq 2>/dev/null)
PQ_LIBS := $(shell $(PKG_CONFIG) --libs libpq 2>/dev/null || echo "-lpq")

# OpenSSL flags
SSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
SSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

# Combine all flags
CFLAGS += $(PQ_CFLAGS) $(SSL_CFLAGS)
LDFLAGS = $(PQ_LIBS) $(SSL_LIBS) -lcrypt

# Build directories (absolute path for sub-makefiles)
ROOT_DIR := $(shell pwd)
BUILD_DIR = $(ROOT_DIR)/build
BIN_DIR = $(BUILD_DIR)/bin
LIB_DIR = $(BUILD_DIR)/lib
OBJ_DIR = $(BUILD_DIR)/obj

# Source directories
SRC_LIB = lib
SRC_SMTP = src
SRC_WEB = web
SRC_UNIFIED = unified
SRC_CXC = web/src_cxc

export BUILD_DIR CC CFLAGS LDFLAGS PKG_CONFIG

.PHONY: all dirs lib smtp web unified cxc clean help

all: dirs lib smtp web

dirs:
	@mkdir -p $(BIN_DIR) $(LIB_DIR) $(OBJ_DIR)/lib $(OBJ_DIR)/smtp $(OBJ_DIR)/web $(OBJ_DIR)/unified logs

lib: dirs
	$(MAKE) -C $(SRC_LIB)

smtp: dirs lib
	$(MAKE) -C $(SRC_SMTP)

web: dirs lib
	$(MAKE) -C $(SRC_WEB)

unified: dirs lib
	$(MAKE) -C $(SRC_UNIFIED)

cxc: dirs
	$(CC) $(CFLAGS) -o $(BIN_DIR)/cxc $(SRC_CXC)/main.c

clean:
	rm -rf $(BUILD_DIR)

help:
	@echo "mmail build targets:"
	@echo "  make all      - Build lib, SMTP, and Web servers"
	@echo "  make unified  - Build unified binary (./build/bin/mmail)"
	@echo "  make smtp     - Build SMTP server (./build/bin/mmail-smtp)"
	@echo "  make web      - Build Web server (./build/bin/mmail-web)"
	@echo "  make lib      - Build shared library (./build/lib/libmmail.a)"
	@echo "  make cxc      - Build CX template compiler"
	@echo "  make clean    - Remove build/ directory"
	@echo ""
	@echo "Binaries output to: build/bin/"
	@echo "Logs output to: logs/"
