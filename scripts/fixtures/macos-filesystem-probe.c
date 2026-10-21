/* Independent acceptance metadata, separate from executor implementation. */
#include <sys/mount.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    struct statfs filesystem;
    struct stat directory;
    if (argc != 2 || statfs(argv[1], &filesystem) || stat(argv[1], &directory))
        return 1;
    if (strcmp(filesystem.f_fstypename, "apfs") || !(filesystem.f_flags & MNT_LOCAL))
        return 2;
    printf("{\"filesystem\":\"%s\",\"local\":true,\"flags\":%u,\"device\":%llu}\n",
           filesystem.f_fstypename, filesystem.f_flags, (unsigned long long)directory.st_dev);
    return 0;
}
