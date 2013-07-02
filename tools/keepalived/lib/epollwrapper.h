#ifndef _EPOLLWRAPPER_H_
#define _EPOLLWRAPPER_H_

#include <sys/epoll.h>
#include "timer.h"


#define EPOLL_MAX_FD	50016
#define EPOLL_MAX_EV	50000

/* fd type in struct epfdset */
enum {
	DIR_RD=0,
	DIR_WR=1,
	DIR_SIZE
};

/* epoll fd set entry definition */
struct epfdset_entry {
	unsigned int events;
	void *data[DIR_SIZE];
};


#define FD_VALID(X) ((0 <= (X)) && ((X) < EPOLL_MAX_FD))

extern void epoll_init(int *epollfd, struct epoll_event **events);
extern void epoll_cleanup(int *epollfd, struct epoll_event **events);
extern int epoll_handler(int epfd, struct epoll_event *events, TIMEVAL *timer_wait);
extern int epoll_set_fd(int epfd, int dir, int fd, void *data);
extern int epoll_clear_fd(int epfd, int dir, int fd);
extern void *get_data_by_fd(int fd, int dir);
extern int epoll_fdisset(int fd, int dir);

#endif
