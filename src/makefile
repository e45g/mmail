# Build directory (inherited from parent or default)
BUILD_DIR ?= ../build
OBJ_DIR = $(BUILD_DIR)/obj/smtp
BIN_DIR = $(BUILD_DIR)/bin
LIB_BUILD_DIR = $(BUILD_DIR)/lib

CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra
CFLAGS = $(BASE_CFLAGS) -I../lib

# Use pkg-config for portable library detection
PKG_CONFIG ?= pkg-config
PQ_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpq 2>/dev/null)
PQ_LIBS := $(shell $(PKG_CONFIG) --libs libpq 2>/dev/null || echo "-lpq")
SSL_CFLAGS := $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
SSL_LIBS := $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null || echo "-lssl -lcrypto")

CFLAGS += $(PQ_CFLAGS) $(SSL_CFLAGS)

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET = $(BIN_DIR)/mmail-smtp

LDFLAGS = -L$(LIB_BUILD_DIR) -lmmail $(SSL_LIBS) $(PQ_LIBS)

.PHONY: all dirs clean

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
