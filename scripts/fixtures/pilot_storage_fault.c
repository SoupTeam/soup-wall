/* SPDX-License-Identifier: Apache-2.0
 * Test-only Linux loader fixture. No disk filling, mounts or production hooks.
 * Every failure requires an armed regular file and one exact owned pathname.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

static int owned(const char *path) {
    const char *root = getenv("SW_STORAGE_ROOT");
    size_t n = root ? strlen(root) : 0;
    return path && path[0] == '/' && n > 1 && strncmp(root, path, n) == 0
        && path[n] == '/' && !strstr(path, "/../") && !strstr(path, "/./");
}

static int selected(const char *op, const char *path) {
    const char *target = getenv("SW_STORAGE_TARGET");
    const char *arm = getenv("SW_STORAGE_ARM");
    const char *event = getenv("SW_STORAGE_EVENT");
    const char *ops = getenv("SW_STORAGE_OPS");
    struct stat st;
    char needle[40], haystack[128];
    if (!owned(target) || !owned(arm) || !owned(event) || !path || strcmp(path, target)
        || !ops || strlen(ops) > 120) return 0;
    snprintf(needle, sizeof needle, ",%s,", op);
    snprintf(haystack, sizeof haystack, ",%s,", ops);
    if (!strstr(haystack, needle)) return 0;
    if (syscall(SYS_newfstatat, AT_FDCWD, arm, &st, AT_SYMLINK_NOFOLLOW)
        || !S_ISREG(st.st_mode) || st.st_uid != getuid()) return 0;
    return 1;
}

static int fail(const char *op, const char *path) {
    if (!selected(op, path)) return 0;
    const char *value = getenv(!strcmp(op, "unlink") ? "SW_STORAGE_CLEANUP_ERRNO" : "SW_STORAGE_ERRNO");
    int code = value ? atoi(value) : 0;
    if (code != ENOSPC && code != EDQUOT && code != EROFS && code != EACCES) return 0;
    char line[96];
    int n = snprintf(line, sizeof line, "{\"op\":\"%s\",\"errno\":%d}\n", op, code);
    int fd = syscall(SYS_openat, AT_FDCWD, getenv("SW_STORAGE_EVENT"),
        O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0; /* Missing witness must never fabricate a fault. */
    ssize_t count = syscall(SYS_write, fd, line, (size_t)n);
    syscall(SYS_close, fd);
    if (count != n) return 0;
    errno = code;
    return 1;
}

static int fd_path(int fd, char path[PATH_MAX]) {
    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    ssize_t n = syscall(SYS_readlinkat, AT_FDCWD, link, path, PATH_MAX - 1);
    if (n < 0) return 0;
    path[n] = 0;
    return 1;
}

static int at_path(int dir, const char *path, char out[PATH_MAX]) {
    if (!path) return 0;
    if (path[0] == '/') return snprintf(out, PATH_MAX, "%s", path) < PATH_MAX;
    char base[PATH_MAX];
    if (dir == AT_FDCWD) {
        if (!getcwd(base, sizeof base)) return 0;
    } else if (!fd_path(dir, base)) return 0;
    return snprintf(out, PATH_MAX, "%s/%s", base, path) < PATH_MAX;
}

#define OPEN_WRAPPER(name) \
int name(const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if ((flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE)) { \
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); \
    } \
    char full[PATH_MAX]; \
    if ((flags & (O_WRONLY | O_RDWR)) && at_path(AT_FDCWD, path, full) && fail("open", full)) return -1; \
    int (*real)(const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
    return real(path, flags, mode); \
}
OPEN_WRAPPER(open)
OPEN_WRAPPER(open64)

#define OPENAT_WRAPPER(name) \
int name(int dir, const char *path, int flags, ...) { \
    mode_t mode = 0; \
    if ((flags & O_CREAT) || ((flags & O_TMPFILE) == O_TMPFILE)) { \
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); \
    } \
    char full[PATH_MAX]; \
    if ((flags & (O_WRONLY | O_RDWR)) && at_path(dir, path, full) && fail("open", full)) return -1; \
    int (*real)(int, const char *, int, ...) = dlsym(RTLD_NEXT, #name); \
    return real(dir, path, flags, mode); \
}
OPENAT_WRAPPER(openat)
OPENAT_WRAPPER(openat64)

ssize_t write(int fd, const void *buf, size_t size) {
    char path[PATH_MAX];
    if (fd_path(fd, path) && fail("write", path)) return -1;
    ssize_t (*real)(int, const void *, size_t) = dlsym(RTLD_NEXT, "write");
    return real(fd, buf, size);
}

ssize_t writev(int fd, const struct iovec *vec, int count) {
    char path[PATH_MAX];
    if (fd_path(fd, path) && fail("write", path)) return -1;
    ssize_t (*real)(int, const struct iovec *, int) = dlsym(RTLD_NEXT, "writev");
    return real(fd, vec, count);
}

int fsync(int fd) {
    char path[PATH_MAX];
    if (fd_path(fd, path) && fail("fsync", path)) return -1;
    int (*real)(int) = dlsym(RTLD_NEXT, "fsync");
    return real(fd);
}

int fdatasync(int fd) {
    char path[PATH_MAX];
    if (fd_path(fd, path) && fail("fsync", path)) return -1;
    int (*real)(int) = dlsym(RTLD_NEXT, "fdatasync");
    return real(fd);
}

int rename(const char *old, const char *next) {
    char path[PATH_MAX];
    if (at_path(AT_FDCWD, old, path) && fail("rename", path)) return -1;
    int (*real)(const char *, const char *) = dlsym(RTLD_NEXT, "rename");
    return real(old, next);
}

int unlink(const char *file) {
    char path[PATH_MAX];
    if (at_path(AT_FDCWD, file, path) && fail("unlink", path)) return -1;
    int (*real)(const char *) = dlsym(RTLD_NEXT, "unlink");
    return real(file);
}

int unlinkat(int dir, const char *file, int flags) {
    char path[PATH_MAX];
    if (at_path(dir, file, path) && fail("unlink", path)) return -1;
    int (*real)(int, const char *, int) = dlsym(RTLD_NEXT, "unlinkat");
    return real(dir, file, flags);
}
