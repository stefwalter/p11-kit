/*
 * Copyright (c) 2005 Stefan Walter
 * Copyright (c) 2011 Collabora Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 *
 * CONTRIBUTORS
 *  Stef Walter <stef@memberwebs.com>
 */

#include "config.h"

typedef struct {
	pthread_t *thread;
	pthread_mutex_t mutex;
	void *action;
} ThreadData

void *
thread_routine (void *arg)
{
	ThreadData *data = arg;

	pthread_mutex_lock (&data->mutex);

	while (data->)
	pthread_mutex_

	pthread_mutex_unlock (&data->mutex);
}

pop_or_create_thread ()
{

}

typedef struct {
	int fd;

} LoopSocket;

typedef struct {
	poll
	hash_map
} LoopContext;

static struct pollfd *
add_poll (struct pollfd **polls,
          int *n_polls,
          int fd,
          short events)
{
	struct pollfd *poll;
	int index;

	(*n_polls)++;
	*polls = xrealloc (*polls, sizeof (struct pollfd) * (*n_polls));
	if (*polls == NULL)
		return NULL;
	poll = *polls + (*n_polls - 1);
	memset (poll, 0, sizeof (struct pollfd));
	poll->fd = fd;
	poll->events = events;
	return poll;
}

typedef struct {
	struct pollfd *polls;
	int n_polls;
} Loop;

typedef void (* LoopIoFunc) (int fd,
                             int revents,
                             void *data);

typedef struct {
	int fd;
	LoopIoFunc callback;
	void *data;
} LoopIo;

Loop *
_p11_loop_init (void)
{
	Loop *loop;

	loop = calloc (1, sizeof (Loop));
	if (loop == NULL)
		return NULL;


}

int
_p11_loop_add_fd (Loop *loop,
                  int fd,
                  int events,
                  LoopIoFunc func,
                  void *data)
{
	struct pollfd *polls;
	LoopIo *io;

	polls = realloc (loop->polls, sizeof (struct pollfd) * loop->n_polls + 1);
	if (polls == NULL) {
		errno = ENOMEM;
		return -1;
	}

	loop->polls = polls;
	io = calloc (1, sizeof (LoopIo));
	if (io == NULL) {
		errno = ENOMEM;
		return -1;
	}

	io->callback = func;
	io->fd = fd;
	io->data = data;

	io->events = events;
	memset (polls + loop->n_polls, 0, sizeof (struct pollfd));
	polls[loop->n_polls]
	loop->polls =
}

void
_p11_loop_run (Loop *loop)
{
	struct pollfd *polls;
	int quit = 0;
	int n_polls;
	int ret;

	polls = calloc (2, sizeof (struct pollfd));
	if (polls == NULL)
		fatal ("out of memory while adding polls");

	/* The zero and first polls are special */
	polls[0].fd = master;
	polls[1].fd = signal_pipe[0];
	polls[0].events = polls[1].events = POLLIN;
	n_polls = 2;

	while (!quit) {
		ret = poll (polls, n_polls, -1);
		if (ret < 0)
			fatal ("couldn't poll file descriptors: %s", strerror (errno));

		for (i = 0; i < n_polls; i++) {
			if (poll->revents != 0)
				continue;
			switch (i) {
			case 0:
				ret = accept (poll[i].fd, NULL, NULL);
				if (ret < 0 && errno != EAGAIN)
					fatal ("couldn't accept new connection: %s", strerror (errno));
				xxxxx;
				break;
			case 1:
				ret = read (poll[i].fd, &sig, sizeof (sig));
				if (ret < 0 && errno != EAGAIN)
					fatal ("couldn't read from signal fd: %s", strerror (errno));
				if (ret == sizeof (s) && sig != SIGHUP)
					quit = 1;
				break;
			default:

			}
		}
	}


}
