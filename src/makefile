# Build directory (inherited from parent or default)
BUILD_DIR ?= ../build
OBJ_DIR = $(BUILD_DIR)/obj/smtp
BIN_DIR = $(BUILD_DIR)/bin
LIB_BUILD_DIR = $(BUILD_DIR)/lib

CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2
CFLAGS += -I../lib

SRCS = $(wildcard *.c)
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET = $(BIN_DIR)/mmail-smtp

LDFLAGS = -L$(LIB_BUILD_DIR) -lmmail -lssl -lcrypto -lpq

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
