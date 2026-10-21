/* Acceptance-only syscall boundary. Never linked into the production executable.
 * Darwin interposing forwards unchanged arguments to the real fclonefileat.
 * The parent releases the gate only after independent filesystem observations. */
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

static int gated_clone(int source, int directory, const char *name, uint32_t flags) {
    const char *parent = getenv("SOUP_GATE_PARENT");
    const char *notify_value = getenv("SOUP_GATE_NOTIFY");
    const char *release_value = getenv("SOUP_GATE_RELEASE");
    if (!parent || !notify_value || !release_value || getppid() != (pid_t)atoi(parent))
        return fclonefileat(source, directory, name, flags);
    int notify = atoi(notify_value), release = atoi(release_value);
    struct stat metadata;
    if (fstat(source, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 0) {
        errno = EINVAL;
        return -1;
    }
    dprintf(notify, "{\"stage\":true,\"links\":%u,\"size\":%lld}\n",
            (unsigned)metadata.st_nlink, (long long)metadata.st_size);
    char command = 0;
    if (read(release, &command, 1) != 1 || command != 'G') {
        errno = ECANCELED;
        return -1;
    }
    int result = fclonefileat(source, directory, name, flags);
    int saved_errno = result == 0 ? 0 : errno;
    dprintf(notify, "{\"result\":%d,\"errno\":%d}\n", result, saved_errno);
    errno = saved_errno;
    return result;
}

__attribute__((used)) static const struct {
    const void *replacement;
    const void *original;
} interpose[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)&gated_clone, (const void *)&fclonefileat}
};
