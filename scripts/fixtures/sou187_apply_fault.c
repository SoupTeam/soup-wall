// SPDX-License-Identifier: Apache-2.0
// Owned qualification only. No production fault flags or fallback executor.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int published;
static int selected_fd(int fd, const char *expected) {
    if (!expected) return 0;
    char alias[64], actual[4096];
    int size = snprintf(alias, sizeof(alias), "/proc/self/fd/%d", fd);
    if (size <= 0 || (size_t)size >= sizeof(alias)) return 0;
    ssize_t got = readlink(alias, actual, sizeof(actual) - 1);
    if (got < 0) return 0;
    actual[got] = 0;
    return strcmp(actual, expected) == 0;
}
static int mode(const char *expected) {
    const char *value = getenv("SOU187_FAULT");
    return value && strcmp(value, expected) == 0;
}
static void hit(void) {
    const char message[] = "sou187_owned_fault_observed\n";
    (void)write(STDERR_FILENO, message, sizeof(message) - 1);
}
int renameat(int oldfd, const char *oldname, int newfd, const char *newname) {
    int (*original)(int, const char *, int, const char *) = dlsym(RTLD_NEXT, "renameat");
    int selected = strncmp(oldname, ".soup-replace-", 14) == 0
        && selected_fd(oldfd, getenv("SOU187_TARGET_ROOT"))
        && selected_fd(newfd, getenv("SOU187_TARGET_ROOT"));
    if (selected && mode("before-publication")) { hit(); (void)kill(getpid(), SIGKILL); _exit(87); }
    int result = original(oldfd, oldname, newfd, newname);
    if (selected && result == 0) {
        published = 1;
        if (mode("after-publication")) { hit(); (void)kill(getpid(), SIGKILL); _exit(88); }
    }
    return result;
}
int fsync(int fd) {
    int (*original)(int) = dlsym(RTLD_NEXT, "fsync");
    if (published && mode("target-directory-sync")
        && selected_fd(fd, getenv("SOU187_TARGET_ROOT"))) {
        hit(); errno = EIO; return -1;
    }
    if (mode("receipt-sync") && selected_fd(fd, getenv("SOU187_RECEIPT"))) {
        hit(); errno = EIO; return -1;
    }
    return original(fd);
}
