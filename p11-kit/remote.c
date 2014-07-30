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
 * Author: Nikos Mavrogiannopoulos <nmav@redhat.com>
 */

#include "config.h"

#include "compat.h"
#include "buffer.h"
#include "debug.h"
#include "message.h"
#include "p11-kit.h"
#include "remote.h"
#include "rpc.h"
#include "tool.h"
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
serve_module (CK_FUNCTION_LIST *module,
              p11_buffer *options,
              p11_buffer *buffer,
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

		if (!p11_rpc_server_handle (&virt->funcs, buffer, buffer)) {
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

static void
cleanup_children (void)
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

static void
handle_children (int signo)
{
	need_children_cleanup = 1;
}

int
p11_kit_remote_serve_module (CK_FUNCTION_LIST *module,
                             const char *socket_file)
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

#if 0
	rc = chown(SOCKET_FILE, config->uid, config->gid);
	if (rc == -1) {
		e = errno;
		p11_message ("could not chown socket %s: %s", socket_file, strerror(e));
	}
#endif

	/* run as daemon */
	if (daemon(0,0) == -1) {
		e = errno;
		p11_message ("could not daemonize: %s", strerror(e));
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

		ret = pselect(sd + 1, &rd_set, NULL, NULL, NULL, &emptyset);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret == 0 && children_avail == 0) { /* timeout */
			p11_message ("no connections for 30 secs, exiting");
			exit(0);
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

		/* XXX: check the uid of the peer */

		pid = fork();
		switch(pid) {
			case -1:
				 p11_message_err (errno, "failed to fork for accept");
				 continue;
			case 0:
				/* child */
				sigprocmask(SIG_UNBLOCK, &blockset, NULL);
				serve_module (module, &options, &buffer, &virt, cfd);
				_exit(0);
			default:
				children_avail++;
				break;
		}
		close(cfd);
	}

	p11_buffer_uninit (&buffer);
	p11_buffer_uninit (&options);
	p11_virtual_uninit (&virt);

	return ret;
}

int
main (int argc,
      char *argv[])
{
	CK_FUNCTION_LIST *module;
	char *socket_file = NULL;
	int opt;
	int ret;

	enum {
		opt_verbose = 'v',
		opt_help = 'h',
		opt_socket = 's',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, opt_help },
		{ "socket", required_argument, NULL, opt_socket },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit remote <module> -s <socket-file>" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_socket:
			socket_file = strdup(optarg);
			break;
		case opt_help:
		case '?':
			p11_tool_usage (usages, options);
			return 0;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1) {
		p11_message ("specify the module to remote");
		return 2;
	}

	if (socket_file == NULL) {
		p11_tool_usage (usages, options);
		return 2;
	}

	module = p11_kit_module_load (argv[0], 0);
	if (module == NULL)
		return 1;

	ret = p11_kit_remote_serve_module (module, getenv ("P11_KIT_SOCKET"));
	p11_kit_module_release (module);

	return ret;
}
