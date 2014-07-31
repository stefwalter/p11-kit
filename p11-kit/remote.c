/*
 * Copyright (C) 2014 Red Hat Inc.
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
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "buffer.h"
#include "compat.h"
#include "debug.h"
#include "message.h"
#include "rpc.h"
#include "remote.h"
#include "virtual.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>

#include "unix-peer.h"

#ifdef HAVE_SIGHANDLER_T
# define SIGHANDLER_T sighandler_t
#elif HAVE_SIG_T
# define SIGHANDLER_T sig_t
#elif HAVE___SIGHANDLER_T
# define SIGHANDLER_T __sighandler_t
#else
typedef void (*sighandler_t)(int);
# define SIGHANDLER_T sighandler_t
#endif

static unsigned need_children_cleanup = 0;
static unsigned children_avail = 0;

static
SIGHANDLER_T ocsignal(int signum, SIGHANDLER_T handler)
{
	struct sigaction new_action, old_action;

	new_action.sa_handler = handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction (signum, &new_action, &old_action);
	return old_action.sa_handler;
}

static int
serve_module (const char *name,
	      CK_FUNCTION_LIST *module,
              p11_buffer *options, p11_buffer *buffer,
              p11_virtual *virt,
              int fd)
{
	p11_rpc_status status;
	unsigned char version;
	uint32_t pid;
	size_t state;
	int ret = 1;
	int code;
	struct iovec iov[2];

	switch (read (fd, &version, 1)) {
	case 0:
		status = P11_RPC_EOF;
		goto out;
	case 1:
		if (version != 1) {
			p11_message ("unspported version received: %d", (int)version);
			goto out;
		}
		break;
	default:
		p11_message_err (errno, "couldn't read credential byte");
		goto out;
	}

	version = 0;
	pid = getpid();

	iov[0].iov_base = &version;
	iov[0].iov_len = 1;

	iov[1].iov_base = &pid;
	iov[1].iov_len = 4;

	switch (writev (fd, iov, 2)) {
	case 5:
		break;
	default:
		p11_message_err (errno, "couldn't write credential bytes");
		goto out;
	}

	status = P11_RPC_OK;
	while (status == P11_RPC_OK) {
		state = 0;
		code = 0;

		do {
			status = p11_rpc_transport_read (fd, &state, &code,
			                                 options, buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
			ret = 0;
			continue;
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			p11_message_err (errno, "failed to read rpc message");
			goto out;
		}

		if (!p11_rpc_server_handle (name, &virt->funcs, buffer, buffer)) {
			p11_message ("unexpected error handling rpc message");
			goto out;
		}

		state = 0;
		options->len = 0;
		do {
			status = p11_rpc_transport_write (fd, &state, code,
			                                  options, buffer);
		} while (status == P11_RPC_AGAIN);

		switch (status) {
		case P11_RPC_OK:
			break;
		case P11_RPC_EOF:
		case P11_RPC_AGAIN:
			assert_not_reached ();
		case P11_RPC_ERROR:
			p11_message_err (errno, "failed to write rpc message");
			goto out;
		}
	}

out:
	return ret;
}

static void cleanup_children(void)
{
int status;
pid_t pid;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		if (children_avail > 0)
			children_avail--;
		if (WIFSIGNALED(status)) {
			if (WTERMSIG(status) == SIGSEGV)
				p11_message("child %u died with sigsegv\n", (unsigned)pid);
			else
				p11_message("child %u died with signal %d\n", (unsigned)pid, (int)WTERMSIG(status));
		}
	}
	need_children_cleanup = 0;
}

static void handle_children(int signo)
{
	need_children_cleanup = 1;
}

int
p11_kit_remote_serve_module (CK_FUNCTION_LIST *module,
                             const char *socket_file,
                             uid_t uid,
                             gid_t gid,
                             unsigned foreground,
                             unsigned timeout)
{
	p11_virtual virt;
	p11_buffer options;
	p11_buffer buffer;
	int ret = 1, rc, sd;
	int e, cfd;
	pid_t pid;
	socklen_t sa_len;
	struct sockaddr_un sa;
	fd_set rd_set;
	sigset_t emptyset, blockset;
	uid_t tuid;
	gid_t tgid;
	struct timespec ts;

	sigemptyset(&blockset);
	sigemptyset(&emptyset);
	sigaddset(&blockset, SIGCHLD);
	ocsignal(SIGCHLD, handle_children);

	return_val_if_fail (module != NULL, 1);

	/* listen to unix socket */
	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", socket_file);

	remove(socket_file);

	sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		e = errno;
		p11_message ("could not create socket %s: %s", socket_file, strerror(e));
		return 1;
	}

	umask(066);
	rc = bind(sd, (struct sockaddr *)&sa, SUN_LEN(&sa));
	if (rc == -1) {
		e = errno;
		p11_message ("could not create socket %s: %s", socket_file, strerror(e));
		return 1;
	}

	if (uid != -1 && gid != -1) {
		rc = chown(socket_file, uid, gid);
		if (rc == -1) {
			e = errno;
			p11_message ("could not chown socket %s: %s", socket_file, strerror(e));
			return 1;
		}
	}

	/* run as daemon */
	if (foreground == 0) {
		if (daemon(0,0) == -1) {
			e = errno;
			p11_message ("could not daemonize: %s", strerror(e));
		}
	}

	rc = listen(sd, 1024);
	if (rc == -1) {
		e = errno;
		p11_message ("could not listen to socket %s: %s", socket_file, strerror(e));
		return 1;
	}

	p11_buffer_init (&options, 0);
	p11_buffer_init (&buffer, 0);

	p11_virtual_init (&virt, &p11_virtual_base, module, NULL);

	sigprocmask(SIG_BLOCK, &blockset, NULL);
	/* accept connections */
	for (;;) {
		if (need_children_cleanup)
			cleanup_children();

		FD_ZERO(&rd_set);
		FD_SET(sd, &rd_set);

		ts.tv_sec = timeout;
		ts.tv_nsec = 0;
		ret = pselect(sd + 1, &rd_set, NULL, NULL, &ts, &emptyset);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret == 0 && children_avail == 0) { /* timeout */
			p11_message ("no connections to %s for %u secs, exiting", socket_file, timeout);
			goto exit;
		}

		sa_len = sizeof(sa);
		cfd = accept(sd, (struct sockaddr *)&sa, &sa_len);
		if (cfd == -1) {
			e = errno;
			if (e != EINTR) {
				p11_message ("could not accept from socket %s: %s", socket_file, strerror(e));
			}
			continue;
		}

		/* check the uid of the peer */
		rc = p11_get_upeer_id(cfd, &tuid, &tgid, NULL);
		if (rc == -1) {
			e = errno;
			p11_message ("could not check uid from socket %s: %s", socket_file, strerror(e));
			goto cont;
		}

		if (uid != -1) {
			if (uid != tuid) {
				p11_message ("connecting uid (%u) doesn't match expected (%u)",
					(unsigned)tuid, (unsigned)uid);
				goto cont;
			}
		}

		if (gid != -1) {
			if (gid != tgid) {
				p11_message ("connecting gid (%u) doesn't match expected (%u)",
					(unsigned)tgid, (unsigned)gid);
				goto cont;
			}
		}

		pid = fork();
		switch(pid) {
			case -1:
				 p11_message_err (errno, "failed to fork for accept");
				 continue;
			case 0:
				/* child */
				sigprocmask(SIG_UNBLOCK, &blockset, NULL);
				serve_module (socket_file, module, &options, &buffer, &virt, cfd);
				_exit(0);
			default:
				children_avail++;
				break;
		}
 cont:
		close(cfd);
	}

	p11_buffer_uninit (&buffer);
	p11_buffer_uninit (&options);

	p11_virtual_uninit (&virt);
	return ret;
 exit:
	remove(socket_file);
	exit(0);
}
