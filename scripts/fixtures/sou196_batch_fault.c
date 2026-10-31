// SPDX-License-Identifier: Apache-2.0
// Disposable qualification only; no production fault flags or executor fallback.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int published;
static int changed;
static int mode(const char *s){const char *v=getenv("SOU196_FAULT");return v&&strcmp(s,v)==0;}
static int selected(int fd,const char *expected){
    if(!expected)return 0;
    char alias[64],actual[4096];int n=snprintf(alias,sizeof(alias),"/proc/self/fd/%d",fd);
    if(n<=0||(size_t)n>=sizeof(alias))return 0;
    ssize_t len=readlink(alias,actual,sizeof(actual)-1);if(len<0)return 0;actual[len]=0;return strcmp(actual,expected)==0;
}
static void hit(void){const char msg[]="sou196_owned_fault_observed\n";(void)write(2,msg,sizeof(msg)-1);}
int openat(int fd,const char *name,int flags,...){
    int(*original)(int,const char*,int,...)=dlsym(RTLD_NEXT,"openat");
    mode_t permissions=0;if(flags&O_CREAT){va_list ap;va_start(ap,flags);permissions=(mode_t)va_arg(ap,int);va_end(ap);}
    if(!changed&&(flags&O_CREAT)&&strncmp(name,".soup-replace-",14)==0&&selected(fd,getenv("SOU196_TARGET_ROOT"))&&mode("last-target-during-stage")){
        changed=1;int target=original(fd,"target-1.txt",O_WRONLY|O_TRUNC|O_NOFOLLOW|O_CLOEXEC,0600);
        if(target>=0){const char text[]="Later owned user change.\n";(void)write(target,text,sizeof(text)-1);(void)close(target);hit();}
    }
    if(published&&(flags&O_CREAT)&&strncmp(name,".soup-replace-",14)==0&&selected(fd,getenv("SOU196_TARGET_ROOT"))){
        if(mode("between-publications-kill")){hit();(void)kill(getpid(),SIGKILL);_exit(87);}
        if(mode("between-publications-io")){hit();errno=EIO;return -1;}
    }
    return original(fd,name,flags,permissions);
}
int renameat(int oldfd,const char *oldname,int newfd,const char *newname){
    int(*original)(int,const char*,int,const char*)=dlsym(RTLD_NEXT,"renameat");
    int match=strncmp(oldname,".soup-replace-",14)==0&&selected(oldfd,getenv("SOU196_TARGET_ROOT"))&&selected(newfd,getenv("SOU196_TARGET_ROOT"));
    int result=original(oldfd,oldname,newfd,newname);
    if(match&&result==0){published++;if(mode("after-publication-kill")){hit();(void)kill(getpid(),SIGKILL);_exit(88);}}
    return result;
}
int fsync(int fd){
    int(*original)(int)=dlsym(RTLD_NEXT,"fsync");
    if(mode("receipt-sync")&&selected(fd,getenv("SOU196_DONE"))){hit();errno=EIO;return -1;}
    int result=original(fd);
    if(result==0&&mode("after-receipt-sync")&&selected(fd,getenv("SOU196_DONE"))){hit();(void)kill(getpid(),SIGKILL);_exit(89);}
    return result;
}
