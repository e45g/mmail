TARGET = mmail

CC = gcc
SRCS = $(wildcard src/**.c)
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto -lpq

all: compile run

run:
	./mmail

compile:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)
