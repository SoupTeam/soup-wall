// SPDX-License-Identifier: Apache-2.0
// Opt-in disposable owned CI fixtures only; never linked into the product.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int triggered;
static int mode(const char *name) {
    const char *value = getenv("SOU186_FAULT");
    return value && !strcmp(value, name);
}
static void mark(void) {
    const char *path = getenv("SOU186_FAULT_WITNESS");
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    if (!path) _exit(85);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || real_write(fd, "observed", 8) != 8 || close(fd)) _exit(86);
}
static int path_of(int fd, char path[PATH_MAX]) {
    char alias[64]; snprintf(alias, sizeof(alias), "/proc/self/fd/%d", fd);
    ssize_t n = readlink(alias, path, PATH_MAX - 1);
    if (n < 0) return 0;
    path[n] = 0; return 1;
}
static void sentinel(int dir) {
    ssize_t (*real_write)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    int fd = openat(dir, "unrelated-sentinel", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0 || real_write(fd, "preserve", 8) != 8 || close(fd)) _exit(87);
}
ssize_t write(int fd, const void *bytes, size_t count) {
    ssize_t (*real)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    char path[PATH_MAX];
    if (!triggered && mode("copy-io") && path_of(fd, path) && strstr(path, "/.agentfw-doctor-") && strstr(path, "/result.txt")) {
        triggered = 1; mark(); errno = EIO; return -1;
    }
    return real(fd, bytes, count);
}
int fsync(int fd) {
    int (*real)(int) = dlsym(RTLD_NEXT, "fsync");
    struct stat meta; char path[PATH_MAX], kept[PATH_MAX];
    if (!triggered && !fstat(fd, &meta) && S_ISDIR(meta.st_mode) && path_of(fd,path) && strstr(path,"/.agentfw-doctor-")) {
        if (mode("last-file-change")) {
            const char *target = getenv("SOU186_LAST_OUTPUT");
            int out = target ? open(target, O_WRONLY | O_TRUNC | O_NOFOLLOW) : -1;
            if (out < 0 || write(out,"Changed during staging.\n",24) != 24 || close(out)) _exit(88);
        } else if (mode("cancel")) {
            if (raise(SIGTERM)) _exit(89);
        } else if (mode("extra-entry")) {
            sentinel(fd);
        } else if (mode("swap-stage")) {
            if (snprintf(kept,sizeof(kept),"%s.held",path) >= (int)sizeof(kept) || rename(path,kept) || mkdir(path,0700)) _exit(90);
            int replacement = open(path,O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (replacement < 0) _exit(91);
            sentinel(replacement); close(replacement);
        } else if (mode("redirect-parent")) {
            const char *parent = getenv("SOU186_EXPORT_PARENT");
            if (!parent || snprintf(kept,sizeof(kept),"%s.held",parent) >= (int)sizeof(kept) || rename(parent,kept) || mkdir(parent,0700)) _exit(92);
            int replacement = open(parent,O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (replacement < 0) _exit(93);
            sentinel(replacement); close(replacement);
        } else return real(fd);
        triggered = 1; mark();
    }
    return real(fd);
}
int renameat2(int from, const char *old, int to, const char *dest, unsigned int flags) {
    int (*real)(int, const char *, int, const char *, unsigned int) = dlsym(RTLD_NEXT, "renameat2");
    if (!triggered && (flags & 1) && !strncmp(old,".agentfw-doctor-",16)) {
        if (mode("publish-io")) {triggered = 1; mark(); errno = EIO; return -1;}
        if (mode("concurrent-destination")) {
            if (mkdirat(to,dest,0700)) _exit(94);
            int selected = openat(to,dest,O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
            if (selected < 0) _exit(95);
            sentinel(selected); close(selected); triggered = 1; mark();
        }
    }
    return real(from,old,to,dest,flags);
}
