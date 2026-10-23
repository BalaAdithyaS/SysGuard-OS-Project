#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "syscall_table.h"
#include <string.h>

#if defined(__x86_64__)
static const syscall_entry_t x86_64_syscall_table[] = {
    {0, "read", 3, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"fd", "buf", "count"}},
    {1, "write", 3, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"fd", "buf", "count"}},
    {2, "open", 3, {ARG_TYPE_STR, ARG_TYPE_HEX, ARG_TYPE_OCTAL}, {"filename", "flags", "mode"}},
    {3, "close", 1, {ARG_TYPE_FD}, {"fd"}},
    {4, "stat", 2, {ARG_TYPE_STR, ARG_TYPE_PTR}, {"filename", "statbuf"}},
    {5, "fstat", 2, {ARG_TYPE_FD, ARG_TYPE_PTR}, {"fd", "statbuf"}},
    {6, "lstat", 2, {ARG_TYPE_STR, ARG_TYPE_PTR}, {"filename", "statbuf"}},
    {7, "poll", 3, {ARG_TYPE_PTR, ARG_TYPE_NUM, ARG_TYPE_INT}, {"ufds", "nfds", "timeout"}},
    {8, "lseek", 3, {ARG_TYPE_FD, ARG_TYPE_NUM, ARG_TYPE_INT}, {"fd", "offset", "origin"}},
    {9, "mmap", 6, {ARG_TYPE_HEX, ARG_TYPE_NUM, ARG_TYPE_HEX, ARG_TYPE_HEX, ARG_TYPE_FD, ARG_TYPE_NUM}, {"addr", "len", "prot", "flags", "fd", "off"}},
    {10, "mprotect", 3, {ARG_TYPE_HEX, ARG_TYPE_NUM, ARG_TYPE_HEX}, {"start", "len", "prot"}},
    {11, "munmap", 2, {ARG_TYPE_HEX, ARG_TYPE_NUM}, {"addr", "len"}},
    {12, "brk", 1, {ARG_TYPE_HEX}, {"brk"}},
    {13, "rt_sigaction", 4, {ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"sig", "act", "oact", "sigsetsize"}},
    {14, "rt_sigprocmask", 4, {ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"how", "nset", "oset", "sigsetsize"}},
    {15, "rt_sigreturn", 0, {ARG_TYPE_NONE}, {NULL}},
    {16, "ioctl", 3, {ARG_TYPE_FD, ARG_TYPE_HEX, ARG_TYPE_HEX}, {"fd", "cmd", "arg"}},
    {20, "writev", 3, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"fd", "vec", "vlen"}},
    {21, "access", 2, {ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"filename", "mode"}},
    {22, "pipe", 1, {ARG_TYPE_PTR}, {"fildes"}},
    {23, "select", 5, {ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR}, {"n", "inp", "outp", "exp", "tvp"}},
    {24, "sched_yield", 0, {ARG_TYPE_NONE}, {NULL}},
    {32, "dup", 1, {ARG_TYPE_FD}, {"fildes"}},
    {33, "dup2", 2, {ARG_TYPE_FD, ARG_TYPE_FD}, {"oldfd", "newfd"}},
    {39, "getpid", 0, {ARG_TYPE_NONE}, {NULL}},
    {41, "socket", 3, {ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_INT}, {"family", "type", "protocol"}},
    {42, "connect", 3, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"fd", "uservaddr", "addrlen"}},
    {43, "accept", 3, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_PTR}, {"fd", "upeer_sockaddr", "upeer_addrlen"}},
    {44, "sendto", 6, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM, ARG_TYPE_HEX, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"fd", "buff", "len", "flags", "addr", "addr_len"}},
    {45, "recvfrom", 6, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM, ARG_TYPE_HEX, ARG_TYPE_PTR, ARG_TYPE_PTR}, {"fd", "ubuf", "size", "flags", "addr", "addr_len"}},
    {49, "bind", 3, {ARG_TYPE_FD, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"fd", "umyaddr", "addrlen"}},
    {50, "listen", 2, {ARG_TYPE_FD, ARG_TYPE_INT}, {"fd", "backlog"}},
    {56, "clone", 5, {ARG_TYPE_HEX, ARG_TYPE_HEX, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_HEX}, {"clone_flags", "newsp", "parent_tidptr", "child_tidptr", "tls_val"}},
    {57, "fork", 0, {ARG_TYPE_NONE}, {NULL}},
    {58, "vfork", 0, {ARG_TYPE_NONE}, {NULL}},
    {59, "execve", 3, {ARG_TYPE_STR, ARG_TYPE_PTR, ARG_TYPE_PTR}, {"filename", "argv", "envp"}},
    {60, "exit", 1, {ARG_TYPE_INT}, {"error_code"}},
    {61, "wait4", 4, {ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_INT, ARG_TYPE_PTR}, {"upid", "stat_addr", "options", "ru"}},
    {62, "kill", 2, {ARG_TYPE_INT, ARG_TYPE_INT}, {"pid", "sig"}},
    {63, "uname", 1, {ARG_TYPE_PTR}, {"name"}},
    {72, "fcntl", 3, {ARG_TYPE_FD, ARG_TYPE_HEX, ARG_TYPE_HEX}, {"fd", "cmd", "arg"}},
    {79, "getcwd", 2, {ARG_TYPE_PTR, ARG_TYPE_NUM}, {"buf", "size"}},
    {80, "chdir", 1, {ARG_TYPE_STR}, {"filename"}},
    {82, "rename", 2, {ARG_TYPE_STR, ARG_TYPE_STR}, {"oldname", "newname"}},
    {83, "mkdir", 2, {ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"pathname", "mode"}},
    {84, "rmdir", 1, {ARG_TYPE_STR}, {"pathname"}},
    {85, "creat", 2, {ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"pathname", "mode"}},
    {86, "link", 2, {ARG_TYPE_STR, ARG_TYPE_STR}, {"oldname", "newname"}},
    {87, "unlink", 1, {ARG_TYPE_STR}, {"pathname"}},
    {88, "symlink", 2, {ARG_TYPE_STR, ARG_TYPE_STR}, {"old", "new"}},
    {89, "readlink", 3, {ARG_TYPE_STR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"path", "buf", "bufsiz"}},
    {90, "chmod", 2, {ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"filename", "mode"}},
    {91, "fchmod", 2, {ARG_TYPE_FD, ARG_TYPE_OCTAL}, {"fd", "mode"}},
    {92, "chown", 3, {ARG_TYPE_STR, ARG_TYPE_INT, ARG_TYPE_INT}, {"filename", "user", "group"}},
    {102, "getuid", 0, {ARG_TYPE_NONE}, {NULL}},
    {104, "getgid", 0, {ARG_TYPE_NONE}, {NULL}},
    {107, "geteuid", 0, {ARG_TYPE_NONE}, {NULL}},
    {108, "getegid", 0, {ARG_TYPE_NONE}, {NULL}},
    {137, "statfs", 2, {ARG_TYPE_STR, ARG_TYPE_PTR}, {"pathname", "buf"}},
    {157, "prctl", 5, {ARG_TYPE_INT, ARG_TYPE_HEX, ARG_TYPE_HEX, ARG_TYPE_HEX, ARG_TYPE_HEX}, {"option", "arg2", "arg3", "arg4", "arg5"}},
    {158, "arch_prctl", 2, {ARG_TYPE_HEX, ARG_TYPE_HEX}, {"code", "addr"}},
    {202, "futex", 6, {ARG_TYPE_PTR, ARG_TYPE_INT, ARG_TYPE_NUM, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"uaddr", "op", "val", "utime", "uaddr2", "val3"}},
    {218, "set_tid_address", 1, {ARG_TYPE_PTR}, {"tidptr"}},
    {231, "exit_group", 1, {ARG_TYPE_INT}, {"error_code"}},
    {257, "openat", 4, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_HEX, ARG_TYPE_OCTAL}, {"dfd", "filename", "flags", "mode"}},
    {258, "mkdirat", 3, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"dfd", "pathname", "mode"}},
    {262, "newfstatat", 4, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_PTR, ARG_TYPE_HEX}, {"dfd", "filename", "statbuf", "flag"}},
    {263, "unlinkat", 3, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_HEX}, {"dfd", "pathname", "flag"}},
    {264, "renameat", 4, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_FD, ARG_TYPE_STR}, {"olddfd", "oldname", "newdfd", "newname"}},
    {265, "linkat", 5, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_HEX}, {"olddfd", "oldname", "newdfd", "newname", "flags"}},
    {266, "symlinkat", 3, {ARG_TYPE_STR, ARG_TYPE_FD, ARG_TYPE_STR}, {"oldname", "newdfd", "newname"}},
    {267, "readlinkat", 4, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"dfd", "path", "buf", "bufsiz"}},
    {268, "fchmodat", 3, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"dfd", "filename", "mode"}},
    {269, "faccessat", 3, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_OCTAL}, {"dfd", "filename", "mode"}},
    {273, "pselect6", 6, {ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_PTR}, {"n", "inp", "outp", "exp", "tsp", "sig"}},
    {274, "ppoll", 5, {ARG_TYPE_PTR, ARG_TYPE_NUM, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"ufds", "nfds", "tsp", "sigmask", "sigsetsize"}},
    {293, "pipe2", 2, {ARG_TYPE_PTR, ARG_TYPE_HEX}, {"fildes", "flags"}},
    {302, "prlimit64", 4, {ARG_TYPE_INT, ARG_TYPE_INT, ARG_TYPE_PTR, ARG_TYPE_PTR}, {"pid", "resource", "new_rlim", "old_rlim"}},
    {318, "getrandom", 3, {ARG_TYPE_PTR, ARG_TYPE_NUM, ARG_TYPE_HEX}, {"buf", "count", "flags"}},
    {322, "execveat", 5, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_PTR, ARG_TYPE_PTR, ARG_TYPE_HEX}, {"dfd", "filename", "argv", "envp", "flags"}},
    {332, "statx", 5, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_HEX, ARG_TYPE_HEX, ARG_TYPE_PTR}, {"dfd", "filename", "flags", "mask", "buffer"}},
    {436, "close_range", 3, {ARG_TYPE_NUM, ARG_TYPE_NUM, ARG_TYPE_HEX}, {"first", "last", "flags"}},
    {437, "openat2", 4, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_PTR, ARG_TYPE_NUM}, {"dfd", "filename", "how", "usize"}},
    {439, "faccessat2", 4, {ARG_TYPE_FD, ARG_TYPE_STR, ARG_TYPE_OCTAL, ARG_TYPE_HEX}, {"dfd", "filename", "mode", "flags"}}
};

static const size_t x86_64_table_size = sizeof(x86_64_syscall_table) / sizeof(x86_64_syscall_table[0]);
#endif

int is_supported_architecture(void) {
#if defined(__x86_64__)
    return 1;
#else
    return 0;
#endif
}

const char *get_architecture_name(void) {
#if defined(__x86_64__)
    return "x86_64";
#elif defined(__aarch64__)
    return "aarch64";
#elif defined(__arm__)
    return "arm";
#elif defined(__i386__)
    return "i386";
#else
    return "unknown";
#endif
}

const syscall_entry_t *get_syscall_by_number(long nr) {
#if defined(__x86_64__)
    if (nr < 0) {
        return NULL;
    }
    for (size_t i = 0; i < x86_64_table_size; i++) {
        if (x86_64_syscall_table[i].number == nr) {
            return &x86_64_syscall_table[i];
        }
    }
#else
    (void)nr;
#endif
    return NULL;
}

long get_syscall_number_by_name(const char *name) {
    if (!name) return -1;
#if defined(__x86_64__)
    for (size_t i = 0; i < x86_64_table_size; i++) {
        if (strcmp(x86_64_syscall_table[i].name, name) == 0) {
            return x86_64_syscall_table[i].number;
        }
    }
#else
    (void)name;
#endif
    return -1;
}
