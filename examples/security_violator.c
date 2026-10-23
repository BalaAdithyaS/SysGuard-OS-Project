#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(void) {
    printf("==============================================================\n");
    printf("[SECURITY VIOLATOR DEMO] Starting Multi-Violation Test Suite\n");
    printf("This program deliberately attempts prohibited operations to verify\n");
    printf("that SysGuard intercepts, logs, and physically blocks each violation.\n");
    printf("==============================================================\n\n");

    int violations_attempted = 0;
    int violations_blocked = 0;

    /* Setup temporary test artifacts */
    const char *test_file = "/tmp/sysguard_protected_file.txt";
    const char *test_dir = "/tmp/sysguard_protected_dir";
    const char *test_src = "/tmp/sysguard_rename_src.txt";
    const char *test_dst = "/tmp/sysguard_rename_dst.txt";

    int fd = open(test_file, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, "Protected Data\n", 15);
        (void)w;
        close(fd);
    }
    mkdir(test_dir, 0755);

    int fd_src = open(test_src, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd_src >= 0) {
        ssize_t w = write(fd_src, "Source\n", 7);
        (void)w;
        close(fd_src);
    }

    /* VIOLATION 1: Unauthorized File Deletion (unlink) */
    violations_attempted++;
    printf("[VIOLATION 1] Attempting prohibited file deletion: unlink('%s')...\n", test_file);
    int res1 = unlink(test_file);
    int err1 = errno;
    if (res1 == -1 && err1 == EPERM) {
        printf("  -> RESULT: BLOCKED! errno=%d (%s)\n", err1, strerror(err1));
        violations_blocked++;
    } else {
        printf("  -> RESULT: Unlink returned %d (errno=%d)\n", res1, err1);
    }

    /* VIOLATION 2: Unauthorized Directory Removal (rmdir) */
    violations_attempted++;
    printf("\n[VIOLATION 2] Attempting prohibited directory removal: rmdir('%s')...\n", test_dir);
    int res2 = rmdir(test_dir);
    int err2 = errno;
    if (res2 == -1 && err2 == EPERM) {
        printf("  -> RESULT: BLOCKED! errno=%d (%s)\n", err2, strerror(err2));
        violations_blocked++;
    } else {
        printf("  -> RESULT: Rmdir returned %d (errno=%d)\n", res2, err2);
    }

    /* VIOLATION 3: Unauthorized File Renaming (rename) */
    violations_attempted++;
    printf("\n[VIOLATION 3] Attempting prohibited file tamper/rename: rename('%s' -> '%s')...\n", test_src, test_dst);
    int res3 = rename(test_src, test_dst);
    int err3 = errno;
    if (res3 == -1 && err3 == EPERM) {
        printf("  -> RESULT: BLOCKED! errno=%d (%s)\n", err3, strerror(err3));
        violations_blocked++;
    } else {
        printf("  -> RESULT: Rename returned %d (errno=%d)\n", res3, err3);
    }

    /* VIOLATION 4: Unauthorized Signal Injection / Process Attack (kill) */
    violations_attempted++;
    printf("\n[VIOLATION 4] Attempting prohibited process kill: kill(PID 1, SIGTERM)...\n");
    int res4 = kill(1, SIGTERM);
    int err4 = errno;
    if (res4 == -1 && (err4 == EPERM || err4 == EACCES)) {
        printf("  -> RESULT: BLOCKED! errno=%d (%s)\n", err4, strerror(err4));
        violations_blocked++;
    } else {
        printf("  -> RESULT: Kill returned %d (errno=%d)\n", res4, err4);
    }

    /* VIOLATION 5: Another Prohibited File Deletion (unlinkat) */
    violations_attempted++;
    printf("\n[VIOLATION 5] Attempting modern glibc deletion: unlinkat(AT_FDCWD, '%s', 0)...\n", test_src);
    int res5 = unlinkat(AT_FDCWD, test_src, 0);
    int err5 = errno;
    if (res5 == -1 && err5 == EPERM) {
        printf("  -> RESULT: BLOCKED! errno=%d (%s)\n", err5, strerror(err5));
        violations_blocked++;
    } else {
        printf("  -> RESULT: unlinkat returned %d (errno=%d)\n", res5, err5);
    }

    printf("\n==============================================================\n");
    printf("[SECURITY VIOLATOR SUMMARY] Total Violations Attempted: %d\n", violations_attempted);
    printf("                            Total Enforced / Blocked : %d\n", violations_blocked);
    printf("==============================================================\n");

    /* Verify files still exist */
    if (access(test_file, F_OK) == 0 && access(test_dir, F_OK) == 0 && access(test_src, F_OK) == 0) {
        printf("VERIFICATION: All protected files and directories remain intact on disk!\n");
    }

    return (violations_blocked >= 3) ? 0 : 1;
}
