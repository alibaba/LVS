#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/resource.h>

#include "timer.h"
#include "memory.h"
#include "logger.h"
#include "epollwrapper.h"

//int epollfd;
//struct epoll_event *events;
static struct epfdset_entry *epfd_set = NULL;

/* epoll initial */
void epoll_init(int *epollfd, struct epoll_event **events)
{
	struct rlimit limit;

	/* set fd ulimits  */
	limit.rlim_cur = EPOLL_MAX_FD; 
	limit.rlim_max = EPOLL_MAX_FD; 
	if (setrlimit(RLIMIT_NOFILE, &limit) == -1)
		log_message(LOG_INFO, "epoll_init: set limit fd to %d failed.", EPOLL_MAX_FD);

	epfd_set = (struct epfdset_entry *) MALLOC(sizeof(struct epfdset_entry) * EPOLL_MAX_FD);
	if (epfd_set == NULL) {
		log_message(LOG_INFO, "epoll_init: malloc epfd set failed.");
		goto fail_fdset;
	}

	*events = (struct epoll_event *) MALLOC(sizeof(struct epoll_event) * EPOLL_MAX_EV);
	if (*events == NULL) {
		log_message(LOG_INFO, "epoll_init: malloc events set failed.");
		goto fail_events;
	}

	/* Create epoll fd  */
	*epollfd = epoll_create(EPOLL_MAX_FD);
	if(*epollfd == -1) {
		log_message(LOG_INFO, "epoll_init: epoll_create failed.");
		goto fail_epfd;
	}

	return;

fail_epfd:
	FREE(*events);
fail_events:
	FREE(epfd_set);
fail_fdset:
	return;	
}

/* epoll clean up  */
void epoll_cleanup(int *epollfd, struct epoll_event **events)
{
	close(*epollfd);
	*epollfd = -1;
	
	FREE(*events);

	FREE(epfd_set);
}

/* wait epoll events */
int epoll_handler(int epfd, struct epoll_event *events, TIMEVAL *timer_wait)
{
	long timeout;

	timeout = (timer_wait->tv_sec * TIMER_HZ + timer_wait->tv_usec)/1000;
	if ((0 == timeout) && (timer_wait->tv_usec > 0)) {
		select(0, NULL, NULL, NULL, timer_wait);
	}

	return epoll_wait(epfd, events, EPOLL_MAX_EV, timeout);
}

/* epoll set fd */
int epoll_set_fd(int epfd, int dir, int fd, void *data)
{
	int opcode;
	struct epoll_event ev;

	if ( !FD_VALID(fd) ) {
		log_message(LOG_INFO, "epoll_set_fd: fd %d out of range.", fd);
		return -1;
	}

	memset(&ev, 0, sizeof(struct epoll_event));
	ev.data.fd = fd;
	if (dir == DIR_RD)
		ev.events |= EPOLLIN;
	else if (dir == DIR_WR)
		ev.events |= EPOLLOUT;

	if (epfd_set[fd].events == 0) {
		opcode = EPOLL_CTL_ADD;
	} else if( epfd_set[fd].events != ev.events) {
		opcode = EPOLL_CTL_MOD;
	} else {
		/* already exists */
		epfd_set[fd].data[dir] = data;
		return 0;
	}
		

	if (epoll_ctl(epfd, opcode, fd, &ev) != 0) {
		log_message(LOG_INFO, "epoll_set_fd: %s fd %d failure.", 
					(opcode == EPOLL_CTL_ADD) ? "ADD":"MOD", fd);
		return -1;
	}

	epfd_set[fd].events = ev.events;
	epfd_set[fd].data[dir] = data;

	return 0;
}

/* epoll clear fd */
int epoll_clear_fd(int epfd, int dir, int fd)
{
	int opcode;
	struct epoll_event ev;

	if ( !FD_VALID(fd) ) {
		log_message(LOG_INFO, "epoll_clear_fd: fd %d out of range.", fd);
		return -1;
	}

	if (epfd_set[fd].events == 0) {
		log_message(LOG_INFO, "epoll_clear_fd: fd %d is not in fdset.", fd);
		return -1;
	}

	if (dir == DIR_RD)
		epfd_set[fd].events &= ~EPOLLIN;
	else if (dir == DIR_WR)
		epfd_set[fd].events &= ~EPOLLOUT;

	/* clear default ERR/HUP events */
//	epfd_set[fd].events &= ~(EPOLLERR | EPOLLHUP);

	if (epfd_set[fd].events == 0) {
		opcode = EPOLL_CTL_DEL;
		epfd_set[fd].data[dir] = NULL;
	} else {
		opcode = EPOLL_CTL_MOD;
	}

	ev.events = epfd_set[fd].events;
	ev.data.fd = fd;

	if (epoll_ctl(epfd, opcode, fd, &ev) != 0) {
		log_message(LOG_INFO, "epoll_clear_fd: %s fd %d failure.", 
					(opcode == EPOLL_CTL_DEL) ? "DEL":"MOD", fd);
		return -1;
	}

	return 0;
}

void *get_data_by_fd(int fd, int dir)
{
	if ( !FD_VALID(fd) ) {
		log_message(LOG_INFO, "get_data_by_fd: fd %d out of range.", fd);
		return NULL;
	}

	return epfd_set[fd].data[dir];
}

/* if fd is in epoll fdset, return 1, else return 0 */
int epoll_fdisset(int fd, int dir)
{
	if ( !FD_VALID(fd) ) {
		log_message(LOG_INFO, "epoll_fdisset: fd %d out of range.", fd);
		return 0;
	}

	if (((dir == DIR_RD) && ((epfd_set[fd].events & EPOLLIN) == EPOLLIN)) || 
			((dir == DIR_WR) && ((epfd_set[fd].events & EPOLLOUT) == EPOLLOUT)))
		return 1;

	return 0;
}
