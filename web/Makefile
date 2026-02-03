BUILD_DIR ?= ../build
OBJ_DIR = $(BUILD_DIR)/obj/web
BIN_DIR = $(BUILD_DIR)/bin
LIB_BUILD_DIR = $(BUILD_DIR)/lib

CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra

# Use pkg-config for portable library detection
PKG_CONFIG ?= pkg-config
PQ_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpq 2>/dev/null)
PQ_LIBS := $(shell $(PKG_CONFIG) --libs libpq 2>/dev/null || echo "-lpq")

CFLAGS = $(BASE_CFLAGS) $(PQ_CFLAGS) -Isrc -I../lib

SRC_DIR = src

SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/*/*.c)
SRC_FILES = $(notdir $(SRCS))
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

TARGET = $(BIN_DIR)/mmail-web
CXC = $(BIN_DIR)/cxc

LDFLAGS = $(PQ_LIBS) -lcrypt $(LIB_BUILD_DIR)/libmmail.a

.PHONY: all dirs clean cxc

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR)

$(TARGET): $(SRCS) | dirs
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)

cxc: dirs
	$(CC) $(CFLAGS) -o $(CXC) src_cxc/main.c

clean:
	rm -f $(TARGET) $(CXC)
