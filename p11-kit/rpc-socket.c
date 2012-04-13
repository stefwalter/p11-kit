/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2012 Red Hat Inc.

   The Gnome Keyring Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The Gnome Keyring Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.

   Author: Stef Walter <stefw@gnome.org>
*/

#include "config.h"

#include "buffer.h"
#define DEBUG_FLAG DEBUG_RPC
#include "debug.h"
#include "hashmap.h"
#include "private.h"
#include "rpc-message.h"
#include "rpc-socket.h"
#include "unix-credentials.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct _RpcSocket {
	int fd;
	int refs;
	int last_code;
	int sent_creds;
	pthread_mutex_t mutex;
	pthread_cond_t cond;

	/* Filled in if a thread reads data it doesn't own */
	uint32_t header_len;
	uint32_t header_code;
};

static void
rpc_socket_free (void *data)
{
	RpcSocket *sock = data;

	assert (sock != NULL);
	assert (sock->refs == 0);

	/* Free up resources */
	pthread_cond_destroy (&sock->cond);
	pthread_mutex_destroy (&sock->mutex);
	free (sock);
}

static RpcSocket *
rpc_socket_new (int fd)
{
	RpcSocket *sock;

	sock = calloc (1, sizeof (RpcSocket));
	if (sock == NULL)
		return NULL;

	sock->fd = fd;
	sock->last_code = 0x10;

	if (pthread_mutex_init (&sock->mutex, NULL) != 0) {
		free (sock);
		return NULL;
	}

	if (pthread_cond_init (&sock->cond, NULL) != 0) {
		pthread_mutex_destroy (&sock->mutex);
		free (sock);
		return NULL;
	}

	return sock;
}

RpcSocket *
_p11_rpc_socket_open (int fd)
{
	RpcSocket *sock = NULL;

	sock = rpc_socket_new (fd);
	if (sock == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	return _p11_rpc_socket_ref (sock);
}

int
_p11_rpc_socket_is_open (RpcSocket *sock)
{
	assert (sock != NULL);
	return sock->fd >= 0;
}

RpcSocket *
_p11_rpc_socket_ref (RpcSocket *sock)
{
	assert (sock != NULL);

	pthread_mutex_lock (&sock->mutex);
	sock->refs++;
	pthread_mutex_unlock (&sock->mutex);

	return sock;
}

void
_p11_rpc_socket_unref (RpcSocket *sock)
{
	int release = 0;

	assert (sock != NULL);

	/* Unreference the socket */
	pthread_mutex_lock (&sock->mutex);
	if (--sock->refs == 0)
		release = 1;
	pthread_mutex_unlock (&sock->mutex);

	if (release)
		rpc_socket_free (sock);
}

/* Write all data to session socket.  */
static int
write_all (int fd,
           unsigned char* data,
           size_t len)
{
	int r;

	assert (data != NULL);
	assert (len > 0);

	while (len > 0) {
		r = write (fd, data, len);
		if (r == -1) {
			if (errno == EPIPE) {
				_p11_message ("couldn't send data: daemon closed connection");
				return 0;
			} else if (errno != EAGAIN && errno != EINTR) {
				_p11_message ("couldn't send data: %s", strerror (errno));
				return 0;
			}
		} else {
			_p11_debug ("wrote %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return 1;
}

static CK_RV
read_all (int fd,
          unsigned char* data,
          size_t len)
{
	int r;

	assert (data != NULL);
	assert (len > 0);

	while (len > 0) {
		r = read (fd, data, len);
		if (r == 0) {
			_p11_message ("couldn't receive data: daemon closed connection");
			return 0;
		} else if (r == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				_p11_message ("couldn't receive data: %s", strerror (errno));
				return 0;
			}
		} else {
			_p11_debug ("read %d bytes", r);
			data += r;
			len -= r;
		}
	}

	return 1;
}

static CK_RV
rpc_socket_write (RpcSocket *sock,
                  int call_code,
                  RpcMessage *msg)
{
	unsigned char header[8];

	/* The socket is locked and referenced at this point */
	assert (msg != NULL);

	if (!sock->sent_creds) {
		if (_p11_unix_credentials_write (sock->fd) < 0) {
			_p11_message ("couldn't send socket credentials: %s", strerror (errno));
			return CKR_DEVICE_ERROR;
		}
		sock->sent_creds = 1;
	}

	_p11_buffer_encode_uint32 (header, msg->buffer.len + 4);
	_p11_buffer_encode_uint32 (header + 4, call_code);

	if (!write_all (sock->fd, header, 8) ||
	    !write_all (sock->fd, msg->buffer.buf, msg->buffer.len))
		return CKR_DEVICE_ERROR;

	return CKR_OK;
}

static CK_RV
rpc_socket_read (RpcSocket *sock,
                 int call_code,
                 RpcMessage *msg)
{
	unsigned char header[8];

	/* The socket is locked and referenced at this point */

	for (;;) {
		if (sock->header_code == 0) {
			if (!read_all (sock->fd, header, 8))
				return CKR_DEVICE_ERROR;

			sock->header_len = _p11_buffer_decode_uint32 (header);
			sock->header_code = _p11_buffer_decode_uint32 (header + 4);
			if (sock->header_code == 0 || sock->header_len < 4) {
				_p11_message ("received invalid rpc header values: perhaps wrong protocol");
				return CKR_DEVICE_ERROR;
			}
		}

		/* Our header */
		if (sock->header_code == call_code) {
			_p11_rpc_message_reset (msg);
			if (!_p11_buffer_resize (&msg->buffer, sock->header_len)) {
				_p11_message ("couldn't allocate response buffer: out of memory");
				return CKR_HOST_MEMORY;
			}

			if (!read_all (sock->fd, msg->buffer.buf, sock->header_len))
				return CKR_DEVICE_ERROR;

			/* Yay, we got our data, off we go */
			sock->header_code = 0;
			sock->header_len = 0;
			pthread_cond_broadcast (&sock->cond);
			return CKR_OK;
		}

		/* Wait until another thread reads the data for this header */
		if (sock->header_code != 0) {
			pthread_cond_broadcast (&sock->cond);

			if (pthread_cond_wait (&sock->cond, &sock->mutex) != 0)
				return CKR_DEVICE_ERROR;
		}
	}
}

CK_RV
_p11_rpc_socket_send_recv (RpcSocket *sock,
                           RpcMessage *msg)
{
	CK_RV rv = CKR_OK;
	int call_code;

	assert (sock != NULL);
	assert (msg != NULL);

	pthread_mutex_lock (&sock->mutex);
	assert (sock->refs > 0);
	sock->refs++;

	/* Get the next socket reply code */
	call_code = sock->last_code++;

	if (sock->fd == -1)
		rv = CKR_DEVICE_ERROR;
	if (rv == CKR_OK)
		rv = rpc_socket_write (sock, call_code, msg);
	if (rv == CKR_OK)
		rv = rpc_socket_read (sock, call_code, msg);
	if (rv != CKR_OK && sock->fd != -1) {
		_p11_message ("closing socket due to protocol failure");
		close (sock->fd);
		sock->fd = -1;
	}

	sock->refs--;
	assert (sock->refs > 0);
	pthread_mutex_unlock (&sock->mutex);

	return rv;
}
