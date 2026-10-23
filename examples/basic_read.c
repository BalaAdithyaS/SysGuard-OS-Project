#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *path = (argc > 1) ? argv[1] : "/etc/os-release";
    printf("[basic_read] Opening file: %s\n", path);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("[basic_read] open failed");
        return 1;
    }

    char buffer[128];
    ssize_t bytes = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes >= 0) {
        buffer[bytes] = '\0';
        printf("[basic_read] Successfully read %zd bytes.\n", bytes);
    } else {
        perror("[basic_read] read failed");
    }

    close(fd);
    printf("[basic_read] Done.\n");
    return 0;
}
