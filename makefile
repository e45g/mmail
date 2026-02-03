CC = gcc
CFLAGS = -Wall -Wextra -O2 -Ilib
LDFLAGS = -lpq -lssl -lcrypto -lcrypt

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

export BUILD_DIR CC CFLAGS LDFLAGS

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
