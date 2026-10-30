// SPDX-License-Identifier: Apache-2.0
// Qualification-only syscall faults against an explicitly disposable component.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int removed;
static int selected(int fd) {
    const char *root=getenv("SOU188_ROOT");if(!root)return 0;
    char alias[64],actual[4096];
    int n=snprintf(alias,sizeof(alias),"/proc/self/fd/%d",fd);
    if(n<=0 || (size_t)n>=sizeof(alias))return 0;
    ssize_t len=readlink(alias,actual,sizeof(actual)-1);if(len<0)return 0;actual[len]=0;
    return strcmp(root,actual)==0;
}
static int mode(const char *m){const char *v=getenv("SOU188_FAULT");return v&&strcmp(v,m)==0;}
static void hit(void){const char msg[]="sou188_owned_fault_observed\n";(void)write(2,msg,sizeof(msg)-1);}
int unlinkat(int fd,const char *name,int flags){
    int(*original)(int,const char*,int)=dlsym(RTLD_NEXT,"unlinkat");
    if(removed&&mode("between-objects")){hit();(void)kill(getpid(),SIGKILL);_exit(89);}
    int match=selected(fd)&&strcmp(name,"current.json")==0;
    if(match&&mode("before-unlink")){hit();(void)kill(getpid(),SIGKILL);_exit(87);}
    if(match&&mode("unlink-io")){hit();errno=EIO;return -1;}
    int result=original(fd,name,flags);
    if(match&&result==0){removed=1;if(mode("after-unlink")){hit();(void)kill(getpid(),SIGKILL);_exit(88);}}
    return result;
}
int fsync(int fd){int(*original)(int)=dlsym(RTLD_NEXT,"fsync");
    if(removed&&selected(fd)&&mode("directory-sync")){hit();errno=EIO;return -1;}
    return original(fd);
}
