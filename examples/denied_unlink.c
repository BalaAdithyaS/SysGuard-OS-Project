#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *target = (argc > 1) ? argv[1] : "/tmp/sysguard_demo_disposable.txt";
    printf("[denied_unlink] Target disposable file: %s\n", target);

    /* Ensure file exists */
    int fd = open(target, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd >= 0) {
        const char *msg = "SysGuard safety test disposable content\n";
        ssize_t w = write(fd, msg, strlen(msg));
        (void)w;
        close(fd);
    } else {
        perror("[denied_unlink] Warning: could not pre-create file");
    }

    printf("[denied_unlink] Attempting to unlink (delete) '%s'...\n", target);
    int res = unlink(target);
    int err = errno;

    if (res == -1) {
        printf("[denied_unlink] RESULT: unlink failed as expected with errno=%d (%s)\n", err, strerror(err));
        if (access(target, F_OK) == 0) {
            printf("[denied_unlink] VERIFICATION: File is still present on disk. Enforcement verified!\n");
            return 0; /* Expected test success */
        } else {
            printf("[denied_unlink] ERROR: unlink failed but file is missing?\n");
            return 2;
        }
    } else {
        printf("[denied_unlink] WARNING: unlink succeeded! File was deleted! Policy was NOT enforced!\n");
        return 1; /* Failure */
    }
}
