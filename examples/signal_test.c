#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>

static volatile sig_atomic_t g_got_signal = 0;

static void handler(int sig) {
    if (sig == SIGUSR1) {
        g_got_signal = 1;
    }
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handler;
    sigaction(SIGUSR1, &sa, NULL);

    printf("[signal_test] Raising SIGUSR1 to self...\n");
    raise(SIGUSR1);

    if (g_got_signal) {
        printf("[signal_test] Received and handled SIGUSR1 successfully!\n");
        return 0;
    } else {
        fprintf(stderr, "[signal_test] Failed to receive SIGUSR1.\n");
        return 1;
    }
}
