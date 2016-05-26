#include "units.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int init_daemon()
{
	int fd0, fd1, fd2;
	pid_t pid;
	struct rlimit rl;
	unsigned i = 0;
	struct sigaction sa;

    /* set the default authority for create file */
	umask(0);

    /* get the resource */ 
	if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
	{
	    perror("getrlimit() error.\n");
		return -1;
	}

	if ((pid = fork()) < 0)
	{
	    perror("fork() error.\n");
		return -1;
	}
	else if (pid != 0)  /* parent exit */
	{
		exit(0);
	}
    
    /* children continue, become session leader */
	setsid();

	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(SIGHUP, &sa, NULL) < 0)
	{
	    perror("sigaction() error.\n");
		return -1;
	}

	if ((pid = fork()) < 0)
	{
	    perror("fork() error.\n");
		return -1;
	}
	else if (pid != 0) /* parent exit */
	{
		exit(0);
	}
    
    /* change director */
     //chdir("/");

    /* children continue */
	if (rl.rlim_max == RLIM_INFINITY)
	{
		rl.rlim_max = 1024;
	}

    /* close resource */
	for (i = 0; i < rl.rlim_max; ++i)
	{
		close(i);
	}
    
    fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);

	if (fd0 != 0 || fd1 != 1 || fd2 != 2)
	{
	    syslog(LOG_ERR, "unexpected file descriptors %d %d %d.\n", fd0, fd1, fd2);
		return -1;
	}

	return 0;
}

