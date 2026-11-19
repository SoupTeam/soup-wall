// SPDX-License-Identifier: Apache-2.0
// Disposable native witness only. Real publication succeeds first; then either
// withhold subsequent Agent TCP writes or stop before the syscall returns.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

static _Atomic int published = 0;
static void after_commit(const char *leaf) {
    if (strcmp(leaf, "result.txt") != 0) return;
    published = 1;
#if SOU170_FAULT == 2
    kill(getpid(), SIGSTOP);
#endif
}
int linkat(int from, const char *old, int to, const char *dest, int flags) {
    int (*real)(int,const char *,int,const char *,int) = dlsym(RTLD_NEXT,"linkat");
    int result=real(from,old,to,dest,flags);
    if (result==0) after_commit(dest);
    return result;
}
int renameat(int from,const char *old,int to,const char *dest) {
    int (*real)(int,const char *,int,const char *) = dlsym(RTLD_NEXT,"renameat");
    int result=real(from,old,to,dest);
    if (result==0) after_commit(dest);
    return result;
}
static int withhold(int fd) {
#if SOU170_FAULT == 1
    if (published) {
        int saved=errno;
        int type=0;socklen_t length=sizeof(type);
        int socket=getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&length)==0 && type==SOCK_STREAM;
        errno=saved;
        if(socket) {errno=EPIPE;return 1;}
    }
#else
    (void)fd;
#endif
    return 0;
}
ssize_t write(int fd,const void *data,size_t size) {
    ssize_t (*real)(int,const void *,size_t)=dlsym(RTLD_NEXT,"write");
    if(withhold(fd))return -1;
    return real(fd,data,size);
}
ssize_t writev(int fd,const struct iovec *iov,int count) {
    ssize_t (*real)(int,const struct iovec *,int)=dlsym(RTLD_NEXT,"writev");
    if(withhold(fd))return -1;
    return real(fd,iov,count);
}
ssize_t send(int fd,const void *data,size_t size,int flags) {
    ssize_t (*real)(int,const void *,size_t,int)=dlsym(RTLD_NEXT,"send");
    if(withhold(fd))return -1;
    return real(fd,data,size,flags);
}
ssize_t sendmsg(int fd,const struct msghdr *message,int flags) {
    ssize_t (*real)(int,const struct msghdr *,int)=dlsym(RTLD_NEXT,"sendmsg");
    if(withhold(fd))return -1;
    return real(fd,message,flags);
}
