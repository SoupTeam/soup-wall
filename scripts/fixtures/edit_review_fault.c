// SPDX-License-Identifier: Apache-2.0
// Disposable owned qualification only; never loaded by the product.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

ssize_t read(int fd, void *bytes, size_t count) {
    ssize_t (*real)(int, void *, size_t) = dlsym(RTLD_NEXT, "read");
    const char *target = getenv("SOU179_RACE_TARGET");
    const char *outside = getenv("SOU179_RACE_OUTSIDE");
    static int triggered;
    if (target && outside && !triggered) {
        char alias[64], path[PATH_MAX], kept[PATH_MAX];
        snprintf(alias, sizeof(alias), "/proc/self/fd/%d", fd);
        ssize_t n = readlink(alias, path, sizeof(path) - 1);
        if (n > 0) {
            path[n] = 0;
            if (!strcmp(path, target)) {
                triggered = 1;
                if (snprintf(kept, sizeof(kept), "%s.kept", target) >= (int)sizeof(kept)) _exit(87);
                if (rename(target, kept) || symlink(outside, target)) _exit(88);
            }
        }
    }
    return real(fd, bytes, count);
}

int renameat2(int from, const char *old, int to, const char *dest, unsigned int flags) {
    int (*real)(int, const char *, int, const char *, unsigned int) = dlsym(RTLD_NEXT, "renameat2");
    if (getenv("SOU179_EXPORT_IO_FAILURE") && (flags & 1) && !strncmp(old, ".agentfw-doctor-", 16)) {
        errno = EIO;
        return -1;
    }
    return real(from, old, to, dest, flags);
}
