// SPDX-License-Identifier: Apache-2.0
// Test-only syscall failures, loaded exclusively by the disposable native
// witness. Never changes successful bytes/identities or grants authority.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>

static _Atomic int stage_fd = -1;
static _Atomic size_t accepted = 0;
static _Atomic int after_commit = 0;

static int opening(int dir, const char *name, int flags, mode_t mode) {
    int (*real)(int,const char *,int,...) = dlsym(RTLD_NEXT,"openat");
    int fd = real(dir,name,flags,mode);
    if (fd >= 0 && (flags & O_CREAT) && strncmp(name,".soup-replace-",14)==0) {
        stage_fd=fd; accepted=0;
    }
    return fd;
}
int openat(int dir,const char *name,int flags,...) {
    mode_t mode=0;
    if ((flags&O_CREAT) || (flags&O_TMPFILE)==O_TMPFILE) {va_list ap;va_start(ap,flags);mode=va_arg(ap,mode_t);va_end(ap);}
    return opening(dir,name,flags,mode);
}
int openat64(int dir,const char *name,int flags,...) {
    mode_t mode=0;
    if ((flags&O_CREAT) || (flags&O_TMPFILE)==O_TMPFILE) {va_list ap;va_start(ap,flags);mode=va_arg(ap,mode_t);va_end(ap);}
    return opening(dir,name,flags,mode);
}
ssize_t write(int fd,const void *data,size_t size) {
    ssize_t (*real)(int,const void *,size_t)=dlsym(RTLD_NEXT,"write");
#if FAULT == 1
    if (fd==stage_fd) {
        if (accepted>=5) {errno=ENOSPC;return -1;}
        if (size>5-accepted) size=5-accepted;
        ssize_t n=real(fd,data,size);if(n>0) accepted+=(size_t)n;return n;
    }
#endif
    return real(fd,data,size);
}
int close(int fd) {
    int (*real)(int)=dlsym(RTLD_NEXT,"close");
    if(fd==stage_fd) stage_fd=-1;
    return real(fd);
}
int renameat(int from,const char *old,int to,const char *new) {
    int (*real)(int,const char *,int,const char *)=dlsym(RTLD_NEXT,"renameat");
    int selected=strncmp(old,".soup-replace-",14)==0;
#if FAULT == 2
    if(selected) {errno=EIO;return -1;}
#endif
    int result=real(from,old,to,new);
    if(selected && result==0) after_commit=1;
    return result;
}
int fsync(int fd) {
    int (*real)(int)=dlsym(RTLD_NEXT,"fsync");
#if FAULT == 3
    if(after_commit) {after_commit=0;errno=EIO;return -1;}
#endif
    return real(fd);
}
