#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/resource.h>
#include <string.h>
// #include <syslog.h>
#include <errno.h>
#include <sys/file.h>
#include <fcntl.h>

#ifndef _LYDPC_DAEMON_H_INCLUDED_
#define _LYDPC_DAEMON_H_INCLUDED_


static char wkdir[256];
int init_daemon();
void save_pid(int pid);
int get_pid();

void save_pid(int pid)
{
    FILE * fp;
    fp = fopen("lydpc.pid","w+");
    // if(flock(fp->_fileno,LOCK_EX)!=0)
    // {
    //     printf("process already running!\n");
    //     exit(-1);
    // }
    if(fp)
    {
        char buff[10];
        sprintf(buff,"%d",pid);
        fputs(buff,fp);
    }else{
        printf("open pid file failed\n");
    }
    // flock(fp->_fileno,LOCK_UN);
    fclose(fp);


}
int get_pid()
{
    FILE * fp;
    fp = fopen("lydpc.pid","r");
    if(fp)
    {
        char buff[10];
        fgets(buff,10,fp);
        fclose(fp);
        return atoi(buff);
    }else{
        printf("open pid file failed\n");
        fclose(fp);
        return -1;
    }
}

int init_daemon()
{
    // pid_t fpid;
    // struct rlimit r1;
    // int i;
    // int fd0, fd1, fd2;

    // // char wkdir[256];
    // getcwd(wkdir, sizeof(wkdir));
    // printf("process start in %s\n", wkdir);

    // if ( (fpid = fork()) < 0)
    // {
    //     printf("fork failed\n");
    //     return;
    // }
    // else if (fpid > 0)
    // {
    //     exit(0);
    // }

    // if (setsid() < 0)
    // {
    //     printf("setsid failed\n");
    //     return;
    // }

    // if ( (fpid = fork()) < 0)
    // {
    //     printf("fork failed\n");
    //     return;
    // }
    // else if (fpid > 0)
    // {
    //     exit(0);
    // }

    // getrlimit(RLIMIT_NOFILE, &r1);

    // for (i = 0; i < r1.rlim_max; i++)
    // {
    //     close(i);
    // }

    // if (chdir(wkdir) < 0)
    // {
    //     printf("chdir failed\n");
    //     return;
    // }

    // umask(0);

    // if (SIG_ERR == signal(SIGCHLD, SIG_IGN))
    // {
    //     printf("signal failed\n");
    //     return;
    // }

    // if(fpid==0)
    // {
    //     save_pid(getpid());
    // }



    // fd0 = open("dev/null", O_RDWR);
    // fd1 = dup(0);
    // fd2 = dup(0);

    // // openlog(cmd, LOG_CONS|LOG_PID, LOG_DAEMON);
    // if (fd0 != 0 || fd1 != 1 || fd2 != 2)
    // {
    // //     // syslog(LOG_ERR, "unexpected file desc:%d, %d, %d", fd0, fd1, fd2);
    //     exit(1);
    // }

    //syslog(LOG_DEBUG, "***** 中国 ********:%d, %d, %d", fd0, fd1, fd2);
    // return;


    int  fd;
    pid_t pid;

    switch (fork()) {
    case -1:
        return LYDPC_ERROR;

    case 0:
        save_pid(getpid());
        break;

    default:
        exit(0);
    }

    pid = getpid();

    if (setsid() == -1) {
        return LYDPC_ERROR;
    }

    umask(0);

    fd = open("/dev/null", O_RDWR);
    if (fd == -1) {
        return LYDPC_ERROR;
    }

    if (dup2(fd, STDIN_FILENO) == -1) {
        return LYDPC_ERROR;
    }

    if (dup2(fd, STDOUT_FILENO) == -1) {
        return LYDPC_ERROR;
    }

#if 0
    if (dup2(fd, STDERR_FILENO) == -1) {
        return LYDPC_ERROR;
    }
#endif

    if (fd > STDERR_FILENO) {
        if (close(fd) == -1) {
            return LYDPC_ERROR;
        }
    }

    return LYDPC_OK;
}

#endif
