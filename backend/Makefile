CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -pedantic -std=c11 -O2 -D_GNU_SOURCE
TARGET = sysguard-tracer

SRCS = tracer.c syscall_table.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS)

%.o: %.c syscall_table.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
