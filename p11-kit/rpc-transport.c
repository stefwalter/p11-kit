/*
 * Copyright (C) 2012 Stefan Walter
 * Copyright (C) 2013 Red Hat Inc.
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
 * Author: Stef Walter <stefw@gnome.org>
 */

#include "config.h"

#include "argv.h"
#include "compat.h"
#define P11_DEBUG_FLAG P11_DEBUG_RPC
#include "debug.h"
#include "message.h"
#include "pkcs11.h"
#include "private.h"
#include "rnd.h"
#include "unix-peer.h"
#include "rpc.h"
#include "rpc-message.h"

#include <sys/types.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OS_UNIX
#ifdef __linux__
# include <sys/prctl.h>
#endif
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <signal.h>
#include <unistd.h>
#endif

#ifdef OS_WIN32
#include <winsock2.h>
#endif

#ifndef EPROTO
#define EPROTO EIO
#endif

typedef struct {
	/* Never changes */
	int fd;
	pid_t pid;

	/* Protected by the lock */
	p11_mutex_t write_lock;
	int refs;
	int last_code;
	bool sent_creds;

	/* This data is protected by read mutex */
	p11_mutex_t read_lock;
	bool read_creds;
	uint32_t read_code;
	uint32_t read_olen;
	uint32_t read_dlen;
} rpc_socket;

static rpc_socket *
rpc_socket_new (const char *file, unsigned nowait)
{
	rpc_socket *sock;
	struct sockaddr_un sa;
	int ret;
	unsigned i;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", file);

	sock = calloc (1, sizeof (rpc_socket));
	return_val_if_fail (sock != NULL, NULL);

	sock->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock->fd == -1) {
		free(sock);
		p11_message ("could not open socket");
		return_val_if_reached (NULL);
	}

	p11_debug ("connecting to: %s", file);

	/* try to connect to child */
	for (i=0;i<5;i++) {
		ret = connect(sock->fd, (struct sockaddr *)&sa, sizeof(sa));
		if (ret == 0 || nowait != 0)
			break;
		p11_sleep_ms(1000);
	}
	if (ret == -1) {
		close(sock->fd);
		free(sock);
		if (nowait == 0) {
			p11_message ("could not connect to socket: %s", file);
			return_val_if_reached (NULL);
		} else {
			return NULL;
		}
	}

	p11_debug ("connected to: %s", file);

	sock->last_code = 0x10;
	sock->read_creds = false;
	sock->sent_creds = false;
	sock->refs = 1;

	p11_mutex_init (&sock->write_lock);
	p11_mutex_init (&sock->read_lock);

	return sock;
}

#if 0
static rpc_socket *
rpc_socket_ref (rpc_socket *sock)
{
	assert (sock != NULL);

	p11_mutex_lock (&sock->write_lock);
	sock->refs++;
	p11_mutex_unlock (&sock->write_lock);

	return sock;
}

static bool
rpc_socket_is_open (rpc_socket *sock)
{
	assert (sock != NULL);
	return sock->fd >= 0;
}
#endif

static void
rpc_socket_close (rpc_socket *sock)
{
	assert (sock != NULL);

	if (sock->fd != -1) {
		/* kill our peer */
		close (sock->fd);
	}
	sock->fd = -1;
}

static void
rpc_socket_unref (rpc_socket *sock)
{
	int release = 0;

	assert (sock != NULL);

	p11_mutex_lock (&sock->write_lock);
	if (--sock->refs == 0)
		release = 1;
	p11_mutex_unlock (&sock->write_lock);

	if (!release)
		return;

	assert (sock != NULL);
	assert (sock->refs == 0);

	rpc_socket_close (sock);
	p11_mutex_uninit (&sock->write_lock);
	p11_mutex_uninit (&sock->read_lock);
}

static bool
write_all (int fd,
           unsigned char* data,
           size_t len)
{
	int r;

	while (len > 0) {
		r = write (fd, data, len);
		if (r == -1) {
			if (errno == EPIPE) {
				p11_message ("couldn't send data: closed connection");
				return false;
			} else if (errno != EAGAIN && errno != EINTR) {
				p11_message_err (errno, "couldn't send data");
				return false;
			}
		} else {
			p11_debug ("wrote %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return true;
}

static bool
read_all (int fd,
          unsigned char* data,
          size_t len)
{
	int r;

	while (len > 0) {
		r = read (fd, data, len);
		if (r == 0) {
			p11_message ("couldn't receive data: closed connection");
			return false;
		} else if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				p11_message_err (errno, "couldn't receive data");
				return false;
			}
		} else {
			p11_debug ("read %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return true;
}

static CK_RV
rpc_socket_write_inlock (rpc_socket *sock,
                         int code,
                         p11_buffer *options,
                         p11_buffer *buffer)
{
	unsigned char header[12];

	/* The socket is locked and referenced at this point */
	assert (buffer != NULL);

	p11_rpc_buffer_encode_uint32 (header, code);
	p11_rpc_buffer_encode_uint32 (header + 4, options->len);
	p11_rpc_buffer_encode_uint32 (header + 8, buffer->len);

	if (!write_all (sock->fd, header, 12) ||
	    !write_all (sock->fd, options->data, options->len) ||
	    !write_all (sock->fd, buffer->data, buffer->len))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static p11_rpc_status
write_at (int fd,
          unsigned char *data,
          size_t len,
          size_t offset,
          size_t *at)
{
	p11_rpc_status status;
	ssize_t num;
	size_t from;
	int errn;

	assert (*at >= offset);

	if (*at >= offset + len)
		return P11_RPC_OK;

	from = *at - offset;
	assert (from < len);

	num = write (fd, data + from, len - from);
	errn = errno;

	/* Update state */
	if (num > 0)
		*at += num;

	/* Completely written out this block */
	if (num == len - from) {
		p11_debug ("ok: wrote block of %d", (int)num);
		status = P11_RPC_OK;

	/* Partially written out this block */
	} else if (num >= 0) {
		p11_debug ("again: partial read of %d", (int)num);
		status = P11_RPC_AGAIN;

	/* Didn't write out block due to transient issue */
	} else if (errn == EINTR || errn == EAGAIN || errn == EWOULDBLOCK) {
		p11_debug ("again: due to %d", errn);
		status = P11_RPC_AGAIN;

	/* Failure */
	} else {
		p11_debug ("error: due to %d", errn);
		status = P11_RPC_ERROR;
	}

	errno = errn;
	return status;
}

p11_rpc_status
p11_rpc_transport_write (int fd,
                         size_t *state,
                         int call_code,
                         p11_buffer *options,
                         p11_buffer *buffer)
{
	unsigned char header[12] = { 0, };
	p11_rpc_status status;

	assert (state != NULL);
	assert (options != NULL);
	assert (buffer != NULL);

	if (*state < 12) {
		p11_rpc_buffer_encode_uint32 (header, call_code);
		p11_rpc_buffer_encode_uint32 (header + 4, options->len);
		p11_rpc_buffer_encode_uint32 (header + 8, buffer->len);
	}

	status = write_at (fd, header, 12, 0, state);

	if (status == P11_RPC_OK) {
		status = write_at (fd, options->data, options->len,
		                   12, state);
	}

	if (status == P11_RPC_OK) {
		status = write_at (fd, buffer->data, buffer->len,
		                   12 + options->len, state);
	}

	/* All done */
	if (status == P11_RPC_OK)
		*state = 0;

	return status;
}

static int
rpc_socket_read (rpc_socket *sock,
                 int *code,
                 p11_buffer *buffer)
{
	CK_RV ret = CKR_DEVICE_ERROR;
	unsigned char header[12];
	fd_set rfds;

	assert (code != NULL);
	assert (buffer != NULL);

	/*
	 * We are not in the main socket lock here, but the socket
	 * is referenced, and won't go away
	 */

	p11_mutex_lock (&sock->read_lock);

	for (;;) {
		/* No message header has been read yet? ... read one in */
		if (sock->read_code == 0) {
			if (!read_all (sock->fd, header, 12))
				break;

			/* Decode and check the message header */
			sock->read_code = p11_rpc_buffer_decode_uint32 (header);
			sock->read_olen = p11_rpc_buffer_decode_uint32 (header + 4);
			sock->read_dlen = p11_rpc_buffer_decode_uint32 (header + 8);
			if (sock->read_code == 0) {
				p11_message ("received invalid rpc header values: perhaps wrong protocol");
				break;
			}
		}

		/* If it's our header (or caller doesn't care), then yay! */
		if (*code == -1 || sock->read_code == *code) {

			/* We ignore the options, so read into the same as buffer */
			if (!p11_buffer_reset (buffer, sock->read_olen) ||
			    !p11_buffer_reset (buffer, sock->read_dlen)) {
				warn_if_reached ();
				break;
			}

			/* Read in the the options first, and then data */
			if (!read_all (sock->fd, buffer->data, sock->read_olen) ||
			    !read_all (sock->fd, buffer->data, sock->read_dlen))
				break;

			buffer->len = sock->read_dlen;
			*code = sock->read_code;

			/* Yay, we got our data, off we go */
			sock->read_code = 0;
			sock->read_olen = 0;
			sock->read_dlen = 0;
			ret = CKR_OK;
			break;
		}

		/* Give another thread the chance to read data for this header */
		if (sock->read_code != 0) {
			p11_debug ("received header in wrong thread");
			p11_mutex_unlock (&sock->read_lock);

			/* Used as a simple wait */
			FD_ZERO (&rfds);
			FD_SET (sock->fd, &rfds);
			if (select (sock->fd + 1, &rfds, NULL, NULL, NULL) < 0)
				p11_message ("couldn't use select to wait on rpc socket");

			p11_mutex_lock (&sock->read_lock);
		}
	}

	p11_mutex_unlock (&sock->read_lock);
	return ret;
}

static p11_rpc_status
read_at (int fd,
         unsigned char *data,
         size_t len,
         size_t offset,
         size_t *at)
{
	p11_rpc_status status;
	int errn;
	ssize_t num;
	size_t from;

	assert (*at >= offset);

	if (*at >= offset + len)
		return P11_RPC_OK;

	from = *at - offset;
	assert (from < len);

	num = read (fd, data + from, len - from);
	errn = errno;

	/* Update state */
	if (num > 0)
		*at += num;

	/* Completely read out this block */
	if (num == len - from) {
		p11_debug ("ok: read block of %d", (int)num);
		status = P11_RPC_OK;

	/* Partially read out this block */
	} else if (num > 0) {
		p11_debug ("again: partial read of %d", (int)num);
		status = P11_RPC_AGAIN;

	/* End of file, valid if at offset zero */
	} else if (num == 0) {
		if (offset == 0) {
			p11_debug ("eof: read zero bytes");
			status = P11_RPC_EOF;
		} else {
			p11_debug ("error: early truncate");
			errn = EPROTO;
			status = P11_RPC_ERROR;
		}

	/* Didn't read out block due to transient issue */
	} else if (errn == EINTR || errn == EAGAIN || errn == EWOULDBLOCK) {
		p11_debug ("again: due to %d", errn);
		status = P11_RPC_AGAIN;

	/* Failure */
	} else {
		p11_debug ("error: due to %d", errn);
		status = P11_RPC_ERROR;
	}

	errno = errn;
	return status;
}

p11_rpc_status
p11_rpc_transport_read (int fd,
                        size_t *state,
                        int *call_code,
                        p11_buffer *options,
                        p11_buffer *buffer)
{
	unsigned char *header;
	p11_rpc_status status;
	size_t len;

	assert (state != NULL);
	assert (call_code != NULL);
	assert (options != NULL);
	assert (buffer != NULL);

	/* Reading the header, we read it into @buffer */
	if (*state < 12) {
		if (!p11_buffer_reset (buffer, 12))
			return_val_if_reached (P11_RPC_ERROR);
		status = read_at (fd, buffer->data, 12, 0, state);
		if (status != P11_RPC_OK)
			return status;

		/* Parse out the header */
		header = buffer->data;
		*call_code = p11_rpc_buffer_decode_uint32 (header);
		len = p11_rpc_buffer_decode_uint32 (header + 4);
		if (!p11_buffer_reset (options, len))
			return_val_if_reached (P11_RPC_ERROR);
		options->len = len;
		len = p11_rpc_buffer_decode_uint32 (header + 8);
		if (!p11_buffer_reset (buffer, len))
			return_val_if_reached (P11_RPC_ERROR);
		buffer->len = len;
	}

	/* At this point options has a valid len field */
	status = read_at (fd, options->data, options->len, 12, state);
	if (status == P11_RPC_OK) {
		status = read_at (fd, buffer->data, buffer->len,
		                  12 + options->len, state);
	}

	if (status == P11_RPC_OK)
		*state = 0;

	return status;
}

struct _p11_rpc_transport {
	p11_rpc_client_vtable vtable;
	p11_destroyer destroyer;
	rpc_socket *socket;
	p11_buffer options;
};

static void
rpc_transport_disconnect (p11_rpc_client_vtable *vtable,
                          void *init_reserved)
{
	p11_rpc_transport *rpc = (p11_rpc_transport *)vtable;

	if (rpc->socket) {
		rpc_socket_close (rpc->socket);
		rpc_socket_unref (rpc->socket);
		rpc->socket = NULL;
	}
}

static bool
rpc_transport_init (p11_rpc_transport *rpc,
                    const char *module_name,
                    p11_destroyer destroyer)
{
	rpc->destroyer = destroyer;

	p11_buffer_init_null (&rpc->options, 0);
	p11_buffer_add (&rpc->options, module_name, -1);
	return_val_if_fail (p11_buffer_ok (&rpc->options), false);

	return true;
}

static void
rpc_transport_uninit (p11_rpc_transport *rpc)
{
	p11_buffer_uninit (&rpc->options);
}

static CK_RV
rpc_transport_buffer (p11_rpc_client_vtable *vtable,
                      p11_buffer *request,
                      p11_buffer *response)
{
	p11_rpc_transport *rpc = (p11_rpc_transport *)vtable;
	CK_RV rv = CKR_OK;
	rpc_socket *sock;
	int call_code;

	assert (rpc != NULL);
	assert (request != NULL);
	assert (response != NULL);

	sock = rpc->socket;
	assert (sock != NULL);

	p11_mutex_lock (&sock->write_lock);
	assert (sock->refs > 0);
	sock->refs++;

	/* Get the next socket reply code */
	call_code = sock->last_code++;

	if (sock->fd == -1)
		rv = CKR_DEVICE_ERROR;
	if (rv == CKR_OK)
		rv = rpc_socket_write_inlock (sock, call_code, &rpc->options, request);

	/* We unlock the socket mutex while reading a response */
	if (rv == CKR_OK) {
		p11_mutex_unlock (&sock->write_lock);

		rv = rpc_socket_read (sock, &call_code, response);

		p11_mutex_lock (&sock->write_lock);
	}

	if (rv != CKR_OK && sock->fd != -1) {
		p11_message ("closing socket due to protocol failure");
		close (sock->fd);
		sock->fd = -1;
	}

	sock->refs--;
	assert (sock->refs > 0);
	p11_mutex_unlock (&sock->write_lock);

	return rv;
}

#ifdef OS_UNIX

typedef struct {
	p11_rpc_transport base;
	char sfile[_POSIX_PATH_MAX];
} rpc_exec;

static void
rpc_disconnect (p11_rpc_client_vtable *vtable,
                     void *fini_reserved)
{
	rpc_exec *rex = (rpc_exec *)vtable;

	if (rex->base.socket)
		rpc_socket_close (rex->base.socket);

	/* Do the common disconnect stuff */
	rpc_transport_disconnect (vtable, fini_reserved);
}

static CK_RV
rpc_connect (p11_rpc_client_vtable *vtable,
                  void *init_reserved)
{
	rpc_exec *rex = (rpc_exec *)vtable;
	int errn;
	unsigned char dummy = 1;
	uint32_t upid;
	struct iovec iov[2];

	p11_debug ("executing rpc transport: %s", (char *)rex->sfile);

	rex->base.socket = rpc_socket_new (rex->sfile, 0);
	return_val_if_fail (rex->base.socket != NULL, CKR_GENERAL_ERROR);

	/* this is read as version from the peer --nmav */
	if (write_all (rex->base.socket->fd, &dummy, 1) != 1) {
		p11_message_err (errno, "couldn't send version");
		return CKR_DEVICE_ERROR;
	}
	rex->base.socket->sent_creds = true;

	iov[0].iov_base = &dummy;
	iov[0].iov_len = 1;
	iov[1].iov_base = &upid;
	iov[1].iov_len = 4;

	errn = readv(rex->base.socket->fd, iov, 2);
	if (errn != 5) {
		p11_message_err (errno, "couldn't read version: %d", errn);
		return CKR_DEVICE_ERROR;
	}
	rex->base.socket->read_creds = true;
	rex->base.socket->pid = upid;

	return CKR_OK;
}

static void
rpc_free (void *data)
{
	rpc_exec *rex = data;
	rpc_disconnect (data, NULL);
	rpc_transport_uninit (&rex->base);
	remove(rex->sfile);
	free (rex);
}

static p11_rpc_transport *
rpc_init (const char *remote,
               const char *name)
{
	rpc_exec *rex;

	rex = calloc (1, sizeof (rpc_exec));
	return_val_if_fail (rex != NULL, NULL);

	snprintf(rex->sfile, sizeof(rex->sfile), "%s", remote);

	rex->base.vtable.connect = rpc_connect;
	rex->base.vtable.disconnect = rpc_disconnect;
	rex->base.vtable.transport = rpc_transport_buffer;
	rpc_transport_init (&rex->base, name, rpc_free);

	p11_debug ("initialized rpc exec: %s", remote);
	return &rex->base;
}

#endif /* OS_UNIX */

p11_rpc_transport *
p11_rpc_transport_new (p11_virtual *virt,
                       const char *remote,
                       const char *name)
{
	p11_rpc_transport *rpc = NULL;

	return_val_if_fail (virt != NULL, NULL);
	return_val_if_fail (remote != NULL, NULL);
	return_val_if_fail (name != NULL, NULL);

#ifdef OS_WIN32
	p11_message ("Windows not yet supported for remote");
	return NULL;
#endif

	/* This is a command we can execute */
	rpc = rpc_init (remote, name);
	if (rpc == NULL) {
		p11_message ("error initializing rpc for: %s", remote);
		return NULL;
	}

	if (!p11_rpc_client_init (virt, &rpc->vtable))
		return_val_if_reached (NULL);

	return rpc;
}

void
p11_rpc_transport_free (void *data)
{
	p11_rpc_transport *rpc = data;

	if (rpc != NULL) {
		assert (rpc->destroyer);
		(rpc->destroyer) (data);
	}
}
