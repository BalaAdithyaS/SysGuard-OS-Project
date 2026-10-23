#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(void) {
    const char *path = "/etc/hosts";
    printf("[audit_only] Attempting to open '%s' under audit policy...\n", path);

    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        printf("[audit_only] Successfully opened fd=%d. Operation was logged and permitted.\n", fd);
        close(fd);
        return 0;
    } else {
        perror("[audit_only] open failed unexpectedly");
        return 1;
    }
}
