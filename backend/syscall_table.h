#ifndef SYSGUARD_SYSCALL_TABLE_H
#define SYSGUARD_SYSCALL_TABLE_H

#include <stddef.h>
#include <stdint.h>

#define MAX_SYSCALL_ARGS 6
#define MAX_STR_LEN 256

typedef enum {
    ARG_TYPE_NONE = 0,
    ARG_TYPE_NUM,
    ARG_TYPE_INT,
    ARG_TYPE_PTR,
    ARG_TYPE_STR,
    ARG_TYPE_FD,
    ARG_TYPE_OCTAL,
    ARG_TYPE_HEX
} arg_type_t;

typedef struct {
    int number;
    const char *name;
    int nargs;
    arg_type_t arg_types[MAX_SYSCALL_ARGS];
    const char *arg_names[MAX_SYSCALL_ARGS];
} syscall_entry_t;

/* Lookup syscall by number */
const syscall_entry_t *get_syscall_by_number(long nr);

/* Lookup syscall number by name */
long get_syscall_number_by_name(const char *name);

/* Check if architecture is supported (x86_64) */
int is_supported_architecture(void);
const char *get_architecture_name(void);

#endif /* SYSGUARD_SYSCALL_TABLE_H */
