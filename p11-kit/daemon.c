/*
 * Copyright (c) 2013, Red Hat Inc.
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

static int
daemon_listen (const char *path)
{
	int sock;
	int ret = -1;

	sock = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		p11_message (errno, "couldn't open socket");
		goto out;
	}

	if (unlink (path) < 0) {
		if (errno != ENOENT) {
			p11_message (errno, "couldn't clear path: %s", path);
			goto out;
		}
	}

	if (bind (sock, (struct sockaddr *)&addr, sizeof (addr)) < 0) {
		p11_message (errno, "couldn't bind to socket: %s", path);
		goto out;
	}

	if (listen (sock, 64) < 0) {
		p11_message (errno, "couldn't listen on socket: %s", path);
		goto out;
	}

	ret = sock;
	sock = -1;

out:
	if (sock >= 0)
		close (sock);
	return ret;
}

typedef struct _rpc_call {
	int code;
	p11_buffer options;
	p11_buffer buffer;
	struct _rpc_call *next;
} rpc_call;

static void
handle_call (p11_

typedef struct {
	int socket;
	rpc_call *in;
	int in_state;
	rpc_call *out;
	int out_state;
} rpc_caller;

static bool
read_caller (rpc_caller *caller)
{
	rpc_call *call;

	if (!caller->in) {
		caller->in = calloc (1, sizeof (rpc_call));
		return_val_if_fail (caller->in != NULL, false);
		p11_buffer_init (&caller->in.options);
		p11_buffer_init (&caller->in.buffer);
		caller->in_state = 0;
	}

	status = p11_rpc_transport_read (caller->socket, &caller->in_state,
	                                 &caller->in.code, &caller->in.options,
	                                 &caller->in.buffer);

	switch (status) {
	case P11_RPC_OK:
		call = caller->in;
		caller->in = NULL;
		caller->in_state = 0
		handle_call (call);
		return true;
	case P11_RPC_EOF:
		return false;
	case P11_RPC_AGAIN:
		return true;
	case P11_RPC_ERROR:
		p11_message (errno, "couldn't read from p11-kit socket");
		return false;
	}
}

static bool
write_caller (rpc_caller *caller)
{
	rpc_call *call;
	int status;

	return_val_if_fail (caller->out != NULL, false);

	status = p11_rpc_transport_write (caller->socket, &caller->out_state,
	                                  &caller->out.options, &caller->out.buffer);

	switch (status) {
	case P11_RPC_OK:
		call = caller->out;
		caller->out = caller->out->next;
		caller->out_state = 0;
		rpc_call_free (call);
		break;
	case P11_RPC_EOF:
		return_val_if_reached (false);
	case P11_RPC_AGAIN:
		return true;
	case P11_RPC_ERROR:
		p11_message (errno, "couldn't write to p11-kit socket");
		return false;
	}
}

static bool
daemon_loop (int master)
{
	struct pollfd *pfds;
	bool ret = false;
	nfds_t nfds;
	int rc;

	pfds = calloc (1, sizeof (struct pollfd));
	return_val_if_fail (pfds != NULL, false);

	pfds[0].fd = master;
	pfds[0].events = POLLIN;
	nfds = 1;

	while (1) {
		for (i = 0; i < nfds; i++)
			pfds[i].revents = 0;

		rc = poll (pfds, nfds, NULL);
		if (rc < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			p11_message (errno, "couldn't poll daemon sockets");
			break;
		}

		for (i = 0; i < nfds && rc > 0; i++) {
			if (pfds[i].revents != 0) {
				rc--;
				if (i == 0) {
					if (accept_socket (master, &sock)) {
						pfds = realloc (pfds, (nfds + 1) * sizeof (struct pollfd));
						return_val_if_fail (pfds != NULL, &pfds);
						memset (pfds + nfds, 0, sizeof (struct pollfd));
						pfds[nfds].fd = sock;
						pfds[nfds].events = POLLIN | POLLOUT | POLLHUP;
					}
				} else {
					if (!handle_socket (pfds[i].fd, pfds[i].revents)) {


					}

						break;
				}
			}
		}
	}

	/* TODO: Shutdown cleanly if SIGTERM */
}

int
main (int argc,
      char **argv)
{
	char *path;
	int master;
	int ret = 0;

	if (asprintf (&path, "/run/user/%d/p11-kit-daemon.sock") < 0)
		return_val_if_reached (1);

	master = daemon_listen (path);
	if (master < 0)
		return 1;

	if (!daemon_loop (master))
		ret = 1;

	free (path);
	close (master);

	return ret;
}
