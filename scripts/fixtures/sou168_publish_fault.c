// SPDX-License-Identifier: Apache-2.0
// Disposable witness only: actual SIGKILL after complete staging, before rename.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

int renameat2(int from, const char *old, int to, const char *dest, unsigned int flags) {
    int (*real)(int, const char *, int, const char *, unsigned int) = dlsym(RTLD_NEXT, "renameat2");
    if ((flags & 1) && strstr(old, "/edit-stage-") != NULL) {
        kill(getpid(), SIGKILL);
        _exit(86);
    }
    return real(from, old, to, dest, flags);
}
