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

static struct pollfd *poll_fds = NULL;
static int n_poll_fds = 0;

static int signal_pipe[2] = { -1, -1 };

static int
nonblock_fd (int fd)
{
	int flags;

	if ((flags = fcntl (fd, F_GETFL)) < 0)
		return -1;
	if (!(flags & O_NONBLOCK)) {
		flags |= O_NONBLOCK;
		if (fcntl(fd, F_SETFL, flags) < 0)
			return -1;
	}

	return 0;
}

static void
signal_handler (int sig)
{
	int save_errno = errno;
	write (signal_pipe[1], &sig, sizeof (sig));
	errno = save_errno;
}

static void
signal_setup (void)
{
	sigset_t ss;
	struct sigaction sa;

	if (pipe (signal_pipe) < 0)
		fatal ("couldn't signal create pipe: %s", strerror (errno));
	if (nonblock_fd (signal_pipe[0]) < 0 || nonblock_fd (signal_pipe[1]))
		fatal ("couldn't change signal pipe to non-blocking: %s", strerror (errno));

	if (sigemptyset (&ss) < 0 ||
	    sigaddset (&ss, SIG_HUP) < 0 ||
	    sigaddset (&ss, SIG_TERM) < 0 ||
	    sigaddset (&ss, SIG_QUIT) < 0 ||
	    sigprocmask (SIG_UNBLOCK, &ss, NULL) < 0)
		fatal ("couldn't unblock signals: %s", strerror (errno));

	memset (&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigemptyset (&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction (SIG_HUP, &sa, NULL) < 0 ||
	    sigaction (SIG_TERM, &sa, NULL) < 0 ||
	    sigaction (SIG_QUIT, &sa, NULL) < 0)
		fatal ("couldn't install signal handlers: %s", strerror (errno));
}

int
main (int argc,
      char *argv[])
{
	Setup logging.

	signal_setup ();

	if (daemonize && daemon(0, 0) == -1) {
		fatal ("couldn't run httpauth as daemon: %s", strerror (errno));
		return 1;
	}


	Start the main loop.
}
