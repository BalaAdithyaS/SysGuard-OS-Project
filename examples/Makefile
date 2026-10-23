CC ?= gcc
CFLAGS ?= -Wall -Wextra -Werror -pedantic -std=c11 -O2

TARGETS = basic_read denied_unlink allowed_operation audit_only signal_test security_violator

.PHONY: all clean

all: $(TARGETS)

basic_read: basic_read.c
	$(CC) $(CFLAGS) -o $@ $<

denied_unlink: denied_unlink.c
	$(CC) $(CFLAGS) -o $@ $<

allowed_operation: allowed_operation.c
	$(CC) $(CFLAGS) -o $@ $<

audit_only: audit_only.c
	$(CC) $(CFLAGS) -o $@ $<

signal_test: signal_test.c
	$(CC) $(CFLAGS) -o $@ $<

security_violator: security_violator.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS)
