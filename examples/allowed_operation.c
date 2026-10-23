#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main(void) {
    pid_t my_pid = getpid();
    printf("[allowed_operation] Successfully retrieved PID: %d\n", (int)my_pid);

    const char *msg = "[allowed_operation] Performing permitted write to stdout.\n";
    ssize_t written = write(STDOUT_FILENO, msg, 58);
    if (written > 0) {
        printf("[allowed_operation] Permitted operation succeeded.\n");
        return 0;
    }
    return 1;
}
