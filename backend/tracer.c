#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "syscall_table.h"

#define SYSGUARD_VERSION "1.0.0"
#define MAX_RULES 128
#define MAX_NAME_LEN 64
#define MAX_JSON_LINE 4096

typedef enum {
    ACTION_ALLOW = 0,
    ACTION_DENY,
    ACTION_AUDIT
} policy_action_t;

typedef struct {
    char syscall_name[MAX_NAME_LEN];
    long syscall_nr;
    policy_action_t action;
} policy_rule_t;

typedef struct {
    char name[128];
    policy_action_t default_action;
    int rule_count;
    policy_rule_t rules[MAX_RULES];
} policy_t;

static volatile sig_atomic_t g_interrupted = 0;
static pid_t g_child_pid = 0;

static void sigint_handler(int sig) {
    (void)sig;
    g_interrupted = 1;
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGTERM);
    }
}

static double get_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void escape_json(const char *src, char *dst, size_t dst_len) {
    size_t j = 0;
    if (!src || !dst || dst_len == 0) return;
    for (size_t i = 0; src[i] != '\0' && j + 2 < dst_len; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '"') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = '"';
        } else if (c == '\\') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = '\\';
        } else if (c == '\n') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = 'n';
        } else if (c == '\r') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = 'r';
        } else if (c == '\t') {
            if (j + 2 >= dst_len) break;
            dst[j++] = '\\'; dst[j++] = 't';
        } else if (c < 32 || c >= 127) {
            if (j + 6 >= dst_len) break;
            snprintf(&dst[j], dst_len - j, "\\u%04x", c);
            j += 6;
        } else {
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
}

static ssize_t read_target_string(pid_t pid, unsigned long addr, char *buf, size_t max_len) {
    if (addr == 0 || buf == NULL || max_len == 0) return -1;
    buf[0] = '\0';

    struct iovec local_iov;
    struct iovec remote_iov;
    local_iov.iov_base = buf;
    local_iov.iov_len = max_len - 1;
    remote_iov.iov_base = (void *)addr;
    remote_iov.iov_len = max_len - 1;

    ssize_t nread = process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
    if (nread > 0) {
        buf[nread] = '\0';
        for (ssize_t i = 0; i < nread; i++) {
            if (buf[i] == '\0') {
                return i;
            }
        }
        buf[max_len - 1] = '\0';
        return nread;
    }

    /* Fallback to PTRACE_PEEKDATA word by word if process_vm_readv is unavailable */
    size_t count = 0;
    while (count < max_len - 1) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, addr + count, NULL);
        if (errno != 0) {
            break;
        }
        char *p = (char *)&word;
        for (size_t b = 0; b < sizeof(long); b++) {
            buf[count] = p[b];
            if (p[b] == '\0') {
                return (ssize_t)count;
            }
            count++;
            if (count >= max_len - 1) break;
        }
    }
    buf[count] = '\0';
    return (count > 0) ? (ssize_t)count : -1;
}

/* Simple robust JSON policy parser for rules */
static int load_policy_file(const char *path, policy_t *pol) {
    memset(pol, 0, sizeof(*pol));
    pol->default_action = ACTION_ALLOW;
    snprintf(pol->name, sizeof(pol->name), "%s", "Default Policy");

    if (!path || strlen(path) == 0) {
        return 0;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "[sysguard-tracer] Warning: Could not open policy file '%s': %s\n", path, strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 1024 * 1024) {
        fclose(f);
        return -1;
    }

    char *content = malloc((size_t)fsize + 1);
    if (!content) {
        fclose(f);
        return -1;
    }

    size_t read_bytes = fread(content, 1, (size_t)fsize, f);
    content[read_bytes] = '\0';
    fclose(f);

    /* Parse policy name if present */
    char *name_ptr = strstr(content, "\"name\"");
    if (name_ptr) {
        char *colon = strchr(name_ptr, ':');
        if (colon) {
            char *quote1 = strchr(colon, '"');
            if (quote1) {
                char *quote2 = strchr(quote1 + 1, '"');
                if (quote2) {
                    size_t name_len = (size_t)(quote2 - quote1 - 1);
                    if (name_len >= sizeof(pol->name)) name_len = sizeof(pol->name) - 1;
                    memcpy(pol->name, quote1 + 1, name_len);
                    pol->name[name_len] = '\0';
                }
            }
        }
    }

    /* Parse default_action */
    char *def_ptr = strstr(content, "\"default_action\"");
    if (def_ptr) {
        char *colon = strchr(def_ptr, ':');
        if (colon) {
            char *quote1 = strchr(colon, '"');
            if (quote1) {
                if (strncmp(quote1 + 1, "deny", 4) == 0) {
                    pol->default_action = ACTION_DENY;
                } else {
                    pol->default_action = ACTION_ALLOW;
                }
            }
        }
    }

    /* Parse rules array */
    char *rules_ptr = strstr(content, "\"rules\"");
    if (rules_ptr) {
        char *p = strchr(rules_ptr, '[');
        while (p && *p != ']' && pol->rule_count < MAX_RULES) {
            char *obj_start = strchr(p, '{');
            if (!obj_start) break;
            char *obj_end = strchr(obj_start, '}');
            if (!obj_end) break;

            char temp_obj[512];
            size_t obj_len = (size_t)(obj_end - obj_start + 1);
            if (obj_len < sizeof(temp_obj)) {
                memcpy(temp_obj, obj_start, obj_len);
                temp_obj[obj_len] = '\0';

                char *sys_key = strstr(temp_obj, "\"syscall\"");
                char *act_key = strstr(temp_obj, "\"action\"");

                if (sys_key && act_key) {
                    char sc_name[MAX_NAME_LEN] = {0};
                    char sc_act[32] = {0};

                    char *q1 = strchr(sys_key, ':');
                    if (q1) q1 = strchr(q1, '"');
                    if (q1) {
                        char *q2 = strchr(q1 + 1, '"');
                        if (q2) {
                            size_t sc_len = (size_t)(q2 - q1 - 1);
                            if (sc_len >= sizeof(sc_name)) sc_len = sizeof(sc_name) - 1;
                            memcpy(sc_name, q1 + 1, sc_len);
                            sc_name[sc_len] = '\0';
                        }
                    }

                    char *aq1 = strchr(act_key, ':');
                    if (aq1) aq1 = strchr(aq1, '"');
                    if (aq1) {
                        char *aq2 = strchr(aq1 + 1, '"');
                        if (aq2) {
                            size_t act_len = (size_t)(aq2 - aq1 - 1);
                            if (act_len >= sizeof(sc_act)) act_len = sizeof(sc_act) - 1;
                            memcpy(sc_act, aq1 + 1, act_len);
                            sc_act[act_len] = '\0';
                        }
                    }

                    if (strlen(sc_name) > 0) {
                        policy_rule_t *r = &pol->rules[pol->rule_count];
                        snprintf(r->syscall_name, sizeof(r->syscall_name), "%s", sc_name);
                        r->syscall_nr = get_syscall_number_by_name(sc_name);

                        if (strcmp(sc_act, "deny") == 0) {
                            r->action = ACTION_DENY;
                        } else if (strcmp(sc_act, "audit") == 0) {
                            r->action = ACTION_AUDIT;
                        } else {
                            r->action = ACTION_ALLOW;
                        }
                        pol->rule_count++;
                    }
                }
            }
            p = obj_end + 1;

        }
    }

    free(content);
    return 0;
}

static policy_action_t evaluate_policy(const policy_t *pol, long syscall_nr, const char *syscall_name, const policy_rule_t **matched_rule) {
    if (matched_rule) *matched_rule = NULL;
    if (!pol) return ACTION_ALLOW;

    for (int i = 0; i < pol->rule_count; i++) {
        const policy_rule_t *r = &pol->rules[i];
        if ((r->syscall_nr >= 0 && r->syscall_nr == syscall_nr) ||
            (syscall_name && strcmp(r->syscall_name, syscall_name) == 0)) {
            if (matched_rule) *matched_rule = r;
            return r->action;
        }
    }
    return pol->default_action;
}

static void print_usage(const char *prog) {
    fprintf(stderr, "SysGuard Native Tracing Backend v%s\n", SYSGUARD_VERSION);
    fprintf(stderr, "Usage: %s [options] -- <command> [args...]\n\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --policy <path>          Path to JSON policy file\n");
    fprintf(stderr, "  -d, --default <allow|deny>   Default action for unlisted syscalls (default: allow)\n");
    fprintf(stderr, "  -a, --audit-only             Audit only (do not nullify denied syscalls)\n");
    fprintf(stderr, "  -e, --errno <EPERM|EACCES>   Error code returned to blocked calls (default: EPERM)\n");
    fprintf(stderr, "  -v, --version                Display version information\n");
    fprintf(stderr, "  -h, --help                   Display this help message\n");
}

int main(int argc, char **argv) {
    if (!is_supported_architecture()) {
        fprintf(stderr, "[sysguard-tracer] Error: Unsupported CPU architecture '%s'. Target requires x86_64.\n", get_architecture_name());
        return 1;
    }

    const char *policy_file = NULL;
    int audit_only = 0;
    int deny_errno = EPERM;
    policy_action_t default_action = ACTION_ALLOW;
    int target_arg_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            target_arg_idx = i + 1;
            break;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--policy") == 0) {
            if (i + 1 < argc) policy_file = argv[++i];
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--audit-only") == 0) {
            audit_only = 1;
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--default") == 0) {
            if (i + 1 < argc) {
                const char *def = argv[++i];
                if (strcmp(def, "deny") == 0) default_action = ACTION_DENY;
                else default_action = ACTION_ALLOW;
            }
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--errno") == 0) {
            if (i + 1 < argc) {
                const char *err_str = argv[++i];
                if (strcmp(err_str, "EACCES") == 0) deny_errno = EACCES;
                else deny_errno = EPERM;
            }
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--version") == 0) {
            printf("{\"event\": \"version\", \"version\": \"%s\", \"arch\": \"%s\"}\n", SYSGUARD_VERSION, get_architecture_name());
            return 0;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            /* If no '--' separator is given but an argument starts without '-', treat as target command */
            if (argv[i][0] != '-') {
                target_arg_idx = i;
                break;
            }
        }
    }

    if (target_arg_idx < 0 || target_arg_idx >= argc) {
        fprintf(stderr, "[sysguard-tracer] Error: No target command specified.\n");
        print_usage(argv[0]);
        return 1;
    }

    policy_t policy;
    load_policy_file(policy_file, &policy);
    if (default_action != ACTION_ALLOW) {
        policy.default_action = default_action;
    }

    /* Check target binary accessibility */
    const char *target_bin = argv[target_arg_idx];
    if (access(target_bin, X_OK) != 0) {
        char *path_env = getenv("PATH");
        int found = 0;
        if (path_env && target_bin[0] != '/' && target_bin[0] != '.') {
            char path_buf[1024];
            char *saveptr;
            char *token = strtok_r(path_env, ":", &saveptr);
            while (token) {
                snprintf(path_buf, sizeof(path_buf), "%s/%s", token, target_bin);
                if (access(path_buf, X_OK) == 0) {
                    target_bin = strdup(path_buf);
                    argv[target_arg_idx] = (char *)target_bin;
                    found = 1;
                    break;
                }
                token = strtok_r(NULL, ":", &saveptr);
            }
        }
        if (!found && access(target_bin, F_OK) != 0) {
            printf("{\"event\": \"error\", \"type\": \"LAUNCH_ERROR\", \"error\": \"Executable not found: %s\", \"timestamp\": %.6f}\n", target_bin, get_timestamp());
            fflush(stdout);
            return 127;
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigint_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    pid_t pid = fork();
    if (pid < 0) {
        printf("{\"event\": \"error\", \"type\": \"FORK_FAILED\", \"error\": \"%s\", \"timestamp\": %.6f}\n", strerror(errno), get_timestamp());
        fflush(stdout);
        return 1;
    }

    if (pid == 0) {
        /* Child process */
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("[sysguard-child] PTRACE_TRACEME failed");
            _exit(1);
        }
        raise(SIGSTOP);
        execv(argv[target_arg_idx], &argv[target_arg_idx]);
        perror("[sysguard-child] execv failed");
        _exit(127);
    }

    g_child_pid = pid;

    /* Parent tracer */
    int status;
    if (waitpid(pid, &status, 0) < 0) {
        printf("{\"event\": \"error\", \"type\": \"WAIT_FAILED\", \"error\": \"%s\", \"timestamp\": %.6f}\n", strerror(errno), get_timestamp());
        fflush(stdout);
        return 1;
    }

    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGSTOP) {
        printf("{\"event\": \"error\", \"type\": \"INITIAL_STOP_UNEXPECTED\", \"status\": %d, \"timestamp\": %.6f}\n", status, get_timestamp());
        fflush(stdout);
        kill(pid, SIGKILL);
        return 1;
    }

    /* Configure ptrace options:
       PTRACE_O_TRACESYSGOOD: deliver (SIGTRAP | 0x80) on syscall stops
       PTRACE_O_TRACEEXEC: deliver event on execve completion
       PTRACE_O_TRACEEXIT: deliver event on process exit
    */
    if (ptrace(PTRACE_SETOPTIONS, pid, 0,
               PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT) < 0) {
        printf("{\"event\": \"error\", \"type\": \"SETOPTIONS_FAILED\", \"error\": \"%s\", \"timestamp\": %.6f}\n", strerror(errno), get_timestamp());
        fflush(stdout);
        kill(pid, SIGKILL);
        return 1;
    }

    /* Emit start event */
    char esc_target[512];
    escape_json(argv[target_arg_idx], esc_target, sizeof(esc_target));
    printf("{\"event\": \"start\", \"pid\": %d, \"target\": \"%s\", \"architecture\": \"%s\", \"policy_name\": \"%s\", \"rule_count\": %d, \"default_action\": \"%s\", \"audit_only\": %s, \"deny_errno\": %d, \"timestamp\": %.6f}\n",
           pid, esc_target, get_architecture_name(), policy.name, policy.rule_count,
           (policy.default_action == ACTION_DENY ? "deny" : "allow"),
           (audit_only ? "true" : "false"), deny_errno, get_timestamp());
    fflush(stdout);

    /* Resume child to execute */
    if (ptrace(PTRACE_SYSCALL, pid, 0, 0) < 0) {
        printf("{\"event\": \"error\", \"type\": \"SYSCALL_RESUME_FAILED\", \"error\": \"%s\", \"timestamp\": %.6f}\n", strerror(errno), get_timestamp());
        fflush(stdout);
        return 1;
    }

    int in_syscall = 0;
    int is_blocked = 0;
    long current_syscall_nr = -1;
    const char *current_syscall_name = "unknown";
    policy_action_t current_action = ACTION_ALLOW;
    const policy_rule_t *current_matched_rule = NULL;
    int total_events = 0;
    int blocked_count = 0;
    int allowed_count = 0;
    int audit_count = 0;
    double start_time = get_timestamp();

    while (!g_interrupted) {
        pid_t wpid = waitpid(pid, &status, 0);
        if (wpid < 0) {
            if (errno == EINTR) {
                if (g_interrupted) break;
                continue;
            }
            break;
        }

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            double end_time = get_timestamp();
            printf("{\"event\": \"exit\", \"pid\": %d, \"exit_code\": %d, \"term_signal\": null, \"total_events\": %d, \"blocked_count\": %d, \"allowed_count\": %d, \"audit_count\": %d, \"duration_ms\": %.2f, \"timestamp\": %.6f}\n",
                   pid, exit_code, total_events, blocked_count, allowed_count, audit_count, (end_time - start_time) * 1000.0, end_time);
            fflush(stdout);
            return exit_code;
        }

        if (WIFSIGNALED(status)) {
            int termsig = WTERMSIG(status);
            double end_time = get_timestamp();
            printf("{\"event\": \"exit\", \"pid\": %d, \"exit_code\": null, \"term_signal\": %d, \"total_events\": %d, \"blocked_count\": %d, \"allowed_count\": %d, \"audit_count\": %d, \"duration_ms\": %.2f, \"timestamp\": %.6f}\n",
                   pid, termsig, total_events, blocked_count, allowed_count, audit_count, (end_time - start_time) * 1000.0, end_time);
            fflush(stdout);
            return 128 + termsig;
        }

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);

            if (sig == (SIGTRAP | 0x80)) {
                /* System call entry or exit */
                struct user_regs_struct regs;
                if (ptrace(PTRACE_GETREGS, pid, 0, &regs) < 0) {
                    fprintf(stderr, "[sysguard-tracer] PTRACE_GETREGS failed: %s\n", strerror(errno));
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                    continue;
                }

                if (!in_syscall) {
                    /* Syscall ENTRY */
                    in_syscall = 1;
                    total_events++;
                    current_syscall_nr = (long)regs.orig_rax;
                    const syscall_entry_t *entry = get_syscall_by_number(current_syscall_nr);
                    current_syscall_name = entry ? entry->name : "unknown";

                    current_action = evaluate_policy(&policy, current_syscall_nr, current_syscall_name, &current_matched_rule);

                    /* Read argument values */
                    unsigned long long args[6] = {
                        regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9
                    };

                    /* Decode first string argument if applicable (e.g. pathname) */
                    char decoded_str[MAX_STR_LEN] = {0};
                    char esc_str[MAX_STR_LEN * 2] = {0};
                    int has_decoded_str = 0;

                    if (entry) {
                        for (int a = 0; a < entry->nargs; a++) {
                            if (entry->arg_types[a] == ARG_TYPE_STR && args[a] != 0) {
                                if (read_target_string(pid, (unsigned long)args[a], decoded_str, sizeof(decoded_str)) >= 0) {
                                    escape_json(decoded_str, esc_str, sizeof(esc_str));
                                    has_decoded_str = 1;
                                }
                                break;
                            }
                        }
                    }

                    const char *decision_str = "ALLOW";
                    const char *enforce_str = "ALLOWED";

                    if (current_action == ACTION_DENY) {
                        decision_str = "DENY";
                        if (!audit_only) {
                            enforce_str = "BLOCKED";
                            is_blocked = 1;
                            blocked_count++;

                            /* Nullify the syscall by setting orig_rax = -1 */
                            regs.orig_rax = (unsigned long long)-1;
                            if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
                                enforce_str = "ENFORCEMENT_FAILED";
                                is_blocked = 0;
                            }
                        } else {
                            enforce_str = "OBSERVED";
                            is_blocked = 0;
                        }
                    } else if (current_action == ACTION_AUDIT) {
                        decision_str = "AUDIT";
                        enforce_str = "OBSERVED";
                        is_blocked = 0;
                        audit_count++;
                    } else {
                        decision_str = "ALLOW";
                        enforce_str = "ALLOWED";
                        is_blocked = 0;
                        allowed_count++;
                    }

                    printf("{\"event\": \"syscall\", \"type\": \"entry\", \"pid\": %d, \"syscall_nr\": %ld, \"syscall_name\": \"%s\", \"args\": [%llu, %llu, %llu, %llu, %llu, %llu], ",
                           pid, current_syscall_nr, current_syscall_name,
                           args[0], args[1], args[2], args[3], args[4], args[5]);
                    if (has_decoded_str) {
                        printf("\"path\": \"%s\", ", esc_str);
                    } else {
                        printf("\"path\": null, ");
                    }
                    printf("\"policy_decision\": \"%s\", \"enforcement\": \"%s\", \"matched_rule\": \"%s\", \"timestamp\": %.6f}\n",
                           decision_str, enforce_str,
                           (current_matched_rule ? current_matched_rule->syscall_name : (policy.default_action == ACTION_DENY ? "default:deny" : "default:allow")),
                           get_timestamp());
                    fflush(stdout);

                } else {
                    /* Syscall EXIT */
                    in_syscall = 0;
                    total_events++;
                    long long ret_val = (long long)regs.rax;
                    const char *enforce_str = "ALLOWED";
                    const char *errno_str = "0";

                    if (is_blocked) {
                        /* Force desired error code (e.g. -EPERM) into rax */
                        regs.rax = (unsigned long long)(-deny_errno);
                        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) < 0) {
                            enforce_str = "ENFORCEMENT_FAILED";
                        } else {
                            enforce_str = "BLOCKED";
                            ret_val = -1;
                            errno_str = (deny_errno == EPERM) ? "EPERM" : "EACCES";
                        }
                        is_blocked = 0;
                    } else if (current_action == ACTION_AUDIT) {
                        enforce_str = "OBSERVED";
                    } else if (current_action == ACTION_DENY && audit_only) {
                        enforce_str = "OBSERVED";
                    }

                    printf("{\"event\": \"syscall\", \"type\": \"exit\", \"pid\": %d, \"syscall_nr\": %ld, \"syscall_name\": \"%s\", \"return_value\": %lld, \"errno\": \"%s\", \"enforcement\": \"%s\", \"timestamp\": %.6f}\n",
                           pid, current_syscall_nr, current_syscall_name,
                           ret_val, errno_str, enforce_str, get_timestamp());
                    fflush(stdout);
                }

                ptrace(PTRACE_SYSCALL, pid, 0, 0);

            } else {
                /* Event stop or signal stop */
                int ptrace_event = (status >> 16) & 0xffff;
                if (ptrace_event == PTRACE_EVENT_EXEC) {
                    /* execve completed into new binary image; syscall exit stop will follow */
                    in_syscall = 1;
                    is_blocked = 0;
                    printf("{\"event\": \"exec_event\", \"pid\": %d, \"timestamp\": %.6f}\n", pid, get_timestamp());
                    fflush(stdout);
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                } else if (ptrace_event == PTRACE_EVENT_EXIT) {
                    /* Process exit pending */
                    ptrace(PTRACE_SYSCALL, pid, 0, 0);
                } else {
                    /* Regular signal delivered to child */
                    if (sig == SIGTRAP) {
                        sig = 0;
                    } else {
                        printf("{\"event\": \"signal\", \"pid\": %d, \"signal\": %d, \"signal_name\": \"%s\", \"timestamp\": %.6f}\n",
                               pid, sig, strsignal(sig), get_timestamp());
                        fflush(stdout);
                    }
                    ptrace(PTRACE_SYSCALL, pid, 0, sig);
                }
            }
        }
    }

    /* If interrupted by user, terminate target child process cleanly */
    if (g_interrupted && pid > 0) {
        printf("{\"event\": \"interrupted\", \"pid\": %d, \"timestamp\": %.6f}\n", pid, get_timestamp());
        fflush(stdout);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }

    return 0;
}
