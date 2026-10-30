// SPDX-License-Identifier: Apache-2.0
// Owned disposable qualification only; never shipped in the normal runtime.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int observations, triggered, outside_seen;
static void mark(const char *path, const char *bytes) {
    ssize_t (*real_write)(int,const void *,size_t)=dlsym(RTLD_NEXT,"write");
    int fd=path?open(path,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW,0600):-1;
    if(fd<0 || real_write(fd,bytes,strlen(bytes))!=(ssize_t)strlen(bytes) || close(fd)) _exit(87);
}
static int exec_blocked;
static void deny_exec(void) {
    if(!exec_blocked) {exec_blocked=1;mark(getenv("SOU189_EXEC_WITNESS"),"exec-attempt");}
    errno=EPERM;
}
int execve(const char *path,char *const argv[],char *const envp[]) {
    (void)path;(void)argv;(void)envp;deny_exec();return -1;
}
int execv(const char *path,char *const argv[]) {
    (void)path;(void)argv;deny_exec();return -1;
}
int execvp(const char *path,char *const argv[]) {
    (void)path;(void)argv;deny_exec();return -1;
}
int posix_spawn(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,
                const posix_spawnattr_t *attributes,char *const argv[],char *const envp[]) {
    (void)pid;(void)path;(void)actions;(void)attributes;(void)argv;(void)envp;deny_exec();return EPERM;
}
int posix_spawnp(pid_t *pid,const char *path,const posix_spawn_file_actions_t *actions,
                 const posix_spawnattr_t *attributes,char *const argv[],char *const envp[]) {
    (void)pid;(void)path;(void)actions;(void)attributes;(void)argv;(void)envp;deny_exec();return EPERM;
}
__attribute__((constructor)) static void loaded(void) {
    mark(getenv("SOU189_LOAD_WITNESS"),"loaded");
    if(getenv("SOU189_OBSERVER_PROBE")) {
        char *const argv[]={(char *)"true",NULL};char *const envp[]={NULL};
        if(execve("/usr/bin/true",argv,envp)!=-1 || errno!=EPERM) _exit(91);
    }
}
ssize_t read(int fd,void *bytes,size_t count) {
    ssize_t (*real)(int,void *,size_t)=dlsym(RTLD_NEXT,"read");
    const char *selected=getenv("SOU189_TRIGGER");
    const char *outside=getenv("SOU189_OUTSIDE");
    const char *mode=getenv("SOU189_MODE");
    char alias[64],path[PATH_MAX],kept[PATH_MAX];
    snprintf(alias,sizeof(alias),"/proc/self/fd/%d",fd);
    ssize_t n=readlink(alias,path,sizeof(path)-1);
    if(n>0) {
        path[n]=0;
        if(outside && !strcmp(path,outside) && !outside_seen) {
            outside_seen=1;mark(getenv("SOU189_OUTSIDE_WITNESS"),"outside-read");
        }
        // Count one stable descriptor observation, excluding its EOF read.
        if(selected && mode && !strcmp(path,selected) && lseek(fd,0,SEEK_CUR)==0) {
            observations++;
            int at=!strcmp(mode,"output-substitution")?1:2;
            if(!triggered && observations==at) {
                triggered=1;
                if(!strcmp(mode,"late-output-change")) {
                    const char *last=getenv("SOU189_LAST_OUTPUT");
                    int out=last?open(last,O_WRONLY|O_TRUNC|O_NOFOLLOW):-1;
                    ssize_t (*real_write)(int,const void *,size_t)=dlsym(RTLD_NEXT,"write");
                    if(out<0 || real_write(out,"Changed during diff.\n",21)!=21 || close(out)) _exit(88);
                } else if(!strcmp(mode,"baseline-parent")) {
                    const char *parent=getenv("SOU189_BASELINE_PARENT");
                    if(!parent || snprintf(kept,sizeof(kept),"%s.held",parent)>=(int)sizeof(kept)
                       || rename(parent,kept) || mkdir(parent,0700)) _exit(89);
                } else {
                    if(!outside || snprintf(kept,sizeof(kept),"%s.kept",selected)>=(int)sizeof(kept)
                       || rename(selected,kept) || symlink(outside,selected)) _exit(90);
                }
                mark(getenv("SOU189_WITNESS"),at==1?"1":"2");
            }
        }
    }
    return real(fd,bytes,count);
}
