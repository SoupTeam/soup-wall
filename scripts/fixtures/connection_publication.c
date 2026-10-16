// SPDX-License-Identifier: Apache-2.0
#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void edit(int dir, const char *name, int fd) {
    int input = open(getenv("SW_PUBLICATION_EDIT"), O_RDONLY);
    if (fd < 0) fd = openat(dir, name, O_WRONLY | O_TRUNC);
    if (input < 0 || fd < 0 || ftruncate(fd, 0) != 0) _exit(90);
    char buffer[4096];
    ssize_t count;
    while ((count = read(input, buffer, sizeof buffer)) > 0) {
        if (write(fd, buffer, count) != count) _exit(91);
    }
    if (count < 0 || fsync(fd) != 0) _exit(92);
    close(input);
    close(fd);
}

int renameat2(int fromdir, const char *from, int todir, const char *to, unsigned int flags) {
    int (*original)(int, const char *, int, const char *, unsigned int) = dlsym(RTLD_NEXT, "renameat2");
    const char *mode = getenv("SW_PUBLICATION_MODE");
    if (!mode || flags != RENAME_EXCHANGE || strcmp(from, "exchanged.json"))
        return original(fromdir, from, todir, to, flags);
    if (!strcmp(mode, "crash-before")) _exit(86);
    if (!strcmp(mode, "write-before")) edit(todir, to, -1);
    if (!strcmp(mode, "replace-before")) {
        char temporary[64];
        snprintf(temporary, sizeof temporary, ".external-%d.json", getpid());
        int fd = openat(todir, temporary, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) _exit(93);
        edit(todir, temporary, fd);
        if (renameat(todir, temporary, todir, to) != 0) _exit(94);
    }
    int held = !strcmp(mode, "held-write-after") ? openat(todir, to, O_WRONLY) : -1;
    if (!strcmp(mode, "held-write-after") && held < 0) _exit(95);
    int result = original(fromdir, from, todir, to, flags);
    if (result != 0) return result;
    if (!strcmp(mode, "crash-after")) _exit(87);
    if (!strcmp(mode, "held-write-after")) edit(todir, to, held);
    if (!strcmp(mode, "write-after")) edit(todir, to, -1);
    return result;
}
