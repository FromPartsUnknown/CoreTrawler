CC = gcc
CFLAGS = -std=c99 -O2
TARGET = coretrawler
SRC = src/coretrawler.c
OS := $(shell uname)

ifeq ($(OS),SunOS)
    CFLAGS += -D_POSIX_PTHREAD_SEMANTICS
endif

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGET)
