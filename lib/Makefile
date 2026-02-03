BUILD_DIR ?= ../build
OBJ_DIR = $(BUILD_DIR)/obj/lib
LIB_DIR = $(BUILD_DIR)/lib

CC ?= gcc
BASE_CFLAGS ?= -Wall -Wextra

# Use pkg-config for portable library detection
PKG_CONFIG ?= pkg-config
PQ_CFLAGS := $(shell $(PKG_CONFIG) --cflags libpq 2>/dev/null)

CFLAGS = $(BASE_CFLAGS) $(PQ_CFLAGS)

AR = ar
ARFLAGS = rcs

SRCS = db.c log.c config.c
OBJS = $(patsubst %.c,$(OBJ_DIR)/%.o,$(SRCS))
TARGET = $(LIB_DIR)/libmmail.a

.PHONY: all clean dirs

all: dirs $(TARGET)

dirs:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR)

$(TARGET): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(OBJ_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
