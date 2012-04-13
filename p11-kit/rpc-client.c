/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* client.c - a PKCS#11 module which communicates with another process

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

#define DEBUG_FLAG DEBUG_RPC
#include "debug.h"
#include "pkcs11.h"
#include "private.h"
#include "rpc-client.h"
#include "rpc-mechanism.h"
#include "rpc-message.h"
#include "rpc-socket.h"
#include "unix-credentials.h"

#include <assert.h>
#include <pthread.h>
#include <string.h>

/* The error used by us when parsing of rpc message fails */
#define PARSE_ERROR   CKR_DEVICE_ERROR

#define return_val_if_fail(x, v) \
	if (!(x)) { _p11_message ("'%s' not true at %s", #x, __func__); return v; }

typedef struct {
	int check;
	CK_FUNCTION_LIST_PTR function_list;
	pthread_mutex_t mutex;
	const RpcClientVtable *vtable;
	RpcSocket *socket;
	pid_t initialized_pid;
} RpcModule;

#define RPC_MODULE_INIT(id, function_list) \
	{ id, (CK_FUNCTION_LIST_PTR)function_list, PTHREAD_MUTEX_INITIALIZER, NULL, 0 }

/* Allocator for call session buffers */
static void*
call_allocator (void *pointer,
                size_t size)
{
	void *result = realloc (pointer, (size_t)size);
	if (!result && size)
		_p11_message ("memory allocation of %lu bytes failed", size);
	return result;
}

static CK_RV
call_prepare (RpcModule *module,
              RpcMessage *msg,
              int call_id)
{
	assert (module != NULL);
	assert (msg != NULL);

	if (!module->socket)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!_p11_rpc_socket_is_open (module->socket))
		return CKR_DEVICE_REMOVED;

	_p11_rpc_socket_ref (module->socket);
	_p11_rpc_message_init (msg, call_allocator);

	/* Put in the Call ID and signature */
	if (!_p11_rpc_message_prep (msg, call_id, RPC_REQUEST))
		return CKR_HOST_MEMORY;

	_p11_debug ("prepared call: %d", call_id);
	return CKR_OK;
}

static CK_RV
call_run (RpcModule *module,
          RpcMessage *msg)
{
	CK_RV ret = CKR_OK;
	CK_ULONG ckerr;
	int call_id;

	assert (module != NULL);
	assert (msg != NULL);

	/* Did building the call fail? */
	if (_p11_rpc_message_buffer_error (msg)) {
		_p11_message ("couldn't allocate request area: out of memory");
		return CKR_HOST_MEMORY;
	}

	/* Make sure that the signature is valid */
	assert (_p11_rpc_message_is_verified (msg));
	call_id = msg->call_id;

	/* Do the dialog with daemon */
	ret = _p11_rpc_socket_send_recv (module->socket, msg);
	if (ret != CKR_OK)
		return ret;

	/* If it's an error code then return it */
	if (msg->call_id == RPC_CALL_ERROR) {
		if (!_p11_rpc_message_read_ulong (msg, &ckerr)) {
			_p11_message ("invalid error response from gnome-keyring-daemon: too short");
			return CKR_DEVICE_ERROR;
		}

		if (ckerr <= CKR_OK) {
			_p11_message ("invalid error response from gnome-keyring-daemon: bad error code");
			return CKR_DEVICE_ERROR;
		}

		/* An error code from the daemon */
		return (CK_RV)ckerr;
	}

	/* Make sure daemon answered the right call */
	if (call_id != msg->call_id) {
		_p11_message ("invalid response from gnome-keyring-daemon: call mismatch");
		return CKR_DEVICE_ERROR;
	}

	assert (!_p11_rpc_message_buffer_error (msg));

	_p11_debug ("parsing response values");
	return CKR_OK;
}

static CK_RV
call_done (RpcModule *module,
           RpcMessage *msg,
           CK_RV ret)
{
	assert (module != NULL);
	assert (msg != NULL);

	/* Check for parsing errors that were not caught elsewhere */
	if (ret == CKR_OK) {
		if (_p11_rpc_message_buffer_error (msg)) {
			_p11_message ("invalid response from gnome-keyring-daemon: bad argument data");
			ret = CKR_GENERAL_ERROR;
		} else {
			/* Double check that the signature matched our decoding */
			assert (_p11_rpc_message_is_verified (msg));
		}
	}

	_p11_rpc_socket_unref (module->socket);
	_p11_rpc_message_clear (msg);
	return ret;
}

/* -----------------------------------------------------------------------------
 * MODULE SPECIFIC PROTOCOL CODE
 */

static CK_RV
proto_read_attribute_array (RpcMessage *msg,
                            CK_ATTRIBUTE_PTR arr,
                            CK_ULONG len)
{
	uint32_t i, num, value, type;
	CK_ATTRIBUTE_PTR attr;
	const unsigned char *attrval;
	size_t attrlen;
	unsigned char validity;
	CK_RV ret;

	assert (len != 0);
	assert (msg != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "aA"));

	/* Get the number of items. We need this value to be correct */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &num))
		return PARSE_ERROR;

	/*
	 * This should never happen in normal operation. It denotes a goof up
	 * on the other side of our RPC. We should be indicating the exact number
	 * of attributes to the other side. And it should respond with the same
	 * number.
	 */
	if (len != num) {
		_p11_message ("received an attribute array with wrong number of attributes");
		return PARSE_ERROR;
	}

	ret = CKR_OK;

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {

		/* The attribute type */
		_p11_buffer_get_uint32 (&msg->buffer, msg->parsed,
		                        &msg->parsed, &type);

		/* Attribute validity */
		_p11_buffer_get_byte (&msg->buffer, msg->parsed,
		                      &msg->parsed, &validity);

		/* And the data itself */
		if (validity) {
			if (_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &value) &&
			    _p11_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, &attrval, &attrlen)) {
				if (attrval && value != attrlen) {
					_p11_message ("attribute length does not match attribute data");
					return PARSE_ERROR;
				}
				attrlen = value;
			}
		}

		/* Don't act on this data unless no errors */
		if (_p11_buffer_has_error (&msg->buffer))
			break;

		/* Try and stuff it in the output data */
		if (arr) {
			attr = &(arr[i]);
			if (attr->type != type) {
				_p11_message ("returned attributes in invalid order");
				return PARSE_ERROR;
			}

			if (validity) {
				/* Just requesting the attribute size */
				if (!attr->pValue) {
					attr->ulValueLen = attrlen;

				/* Wants attribute data, but too small */
				} else if (attr->ulValueLen < attrlen) {
					attr->ulValueLen = attrlen;
					ret = CKR_BUFFER_TOO_SMALL;

				/* Wants attribute data, value is null */
				} else if (attrval == NULL) {
					attr->ulValueLen = 0;

				/* Wants attribute data, enough space */
				} else {
					attr->ulValueLen = attrlen;
					memcpy (attr->pValue, attrval, attrlen);
				}

			/* Not a valid attribute */
			} else {
				attr->ulValueLen = ((CK_ULONG)-1);
			}
		}
	}

	if (_p11_buffer_has_error (&msg->buffer))
		return PARSE_ERROR;

	/* Read in the code that goes along with these attributes */
	if (!_p11_rpc_message_read_ulong (msg, &ret))
		return PARSE_ERROR;

	return ret;
}

static CK_RV
proto_read_byte_array (RpcMessage *msg,
                       CK_BYTE_PTR arr,
                       CK_ULONG_PTR len,
                       CK_ULONG max)
{
	const unsigned char *val;
	unsigned char valid;
	uint32_t length;
	size_t vlen;

	assert (len != NULL);
	assert (msg != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "ay"));

	/* A single byte which determines whether valid or not */
	if (!_p11_buffer_get_byte (&msg->buffer, msg->parsed, &msg->parsed, &valid))
		return PARSE_ERROR;

	/* If not valid, then just the length is encoded, this can signify CKR_BUFFER_TOO_SMALL */
	if (!valid) {
		if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &length))
			return PARSE_ERROR;

		*len = length;

		if (arr)
			return CKR_BUFFER_TOO_SMALL;
		else
			return CKR_OK;
	}

	/* Get the actual bytes */
	if (!_p11_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, &val, &vlen))
		return PARSE_ERROR;

	*len = vlen;

	/* Just asking us for size */
	if (!arr)
		return CKR_OK;

	if (max < vlen)
		return CKR_BUFFER_TOO_SMALL;

	/* Enough space, yay */
	memcpy (arr, val, vlen);
	return CKR_OK;
}

static CK_RV
proto_read_ulong_array (RpcMessage *msg, CK_ULONG_PTR arr,
                        CK_ULONG_PTR len, CK_ULONG max)
{
	uint32_t i, num;
	uint64_t val;
	unsigned char valid;

	assert (len != NULL);
	assert (msg != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "au"));

	/* A single byte which determines whether valid or not */
	if (!_p11_buffer_get_byte (&msg->buffer, msg->parsed, &msg->parsed, &valid))
		return PARSE_ERROR;

	/* Get the number of items. */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &num))
		return PARSE_ERROR;

	*len = num;

	/* If not valid, then just the length is encoded, this can signify CKR_BUFFER_TOO_SMALL */
	if (!valid) {
		if (arr)
			return CKR_BUFFER_TOO_SMALL;
		else
			return CKR_OK;
	}

	if (max < num)
		return CKR_BUFFER_TOO_SMALL;

	/* We need to go ahead and read everything in all cases */
	for (i = 0; i < num; ++i) {
		_p11_buffer_get_uint64 (&msg->buffer, msg->parsed, &msg->parsed, &val);
		if (arr)
			arr[i] = (CK_ULONG)val;
	}

	return _p11_buffer_has_error (&msg->buffer) ? PARSE_ERROR : CKR_OK;
}

static CK_RV
proto_write_mechanism (RpcMessage *msg,
                       CK_MECHANISM_PTR mech)
{
	assert (msg != NULL);
	assert (mech != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "M"));

	/* The mechanism type */
	_p11_buffer_add_uint32 (&msg->buffer, mech->mechanism);

	/*
	 * PKCS#11 mechanism parameters are not easy to serialize. They're
	 * completely different for so many mechanisms, they contain
	 * pointers to arbitrary memory, and many callers don't initialize
	 * them completely or properly.
	 *
	 * We only support certain mechanisms.
	 *
	 * Also callers do yucky things like leaving parts of the structure
	 * pointing to garbage if they don't think it's going to be used.
	 */

	if (_p11_rpc_mechanism_has_no_parameters (mech->mechanism))
		_p11_buffer_add_byte_array (&msg->buffer, NULL, 0);
	else if (_p11_rpc_mechanism_has_sane_parameters (mech->mechanism))
		_p11_buffer_add_byte_array (&msg->buffer, mech->pParameter,
		                           mech->ulParameterLen);
	else
		return CKR_MECHANISM_INVALID;

	return _p11_buffer_has_error (&msg->buffer) ? CKR_HOST_MEMORY : CKR_OK;
}

static CK_RV
proto_read_info (RpcMessage *msg,
                 CK_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_read_version (msg, &info->cryptokiVersion) ||
	    !_p11_rpc_message_read_space_string (msg, info->manufacturerID, 32) ||
	    !_p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !_p11_rpc_message_read_space_string (msg, info->libraryDescription, 32) ||
	    !_p11_rpc_message_read_version (msg, &info->libraryVersion))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_slot_info (RpcMessage *msg,
                      CK_SLOT_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_read_space_string (msg, info->slotDescription, 64) ||
	    !_p11_rpc_message_read_space_string (msg, info->manufacturerID, 32) ||
	    !_p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !_p11_rpc_message_read_version (msg, &info->hardwareVersion) ||
	    !_p11_rpc_message_read_version (msg, &info->firmwareVersion))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_token_info (RpcMessage *msg,
                       CK_TOKEN_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_read_space_string (msg, info->label, 32) ||
	    !_p11_rpc_message_read_space_string (msg, info->manufacturerID, 32) ||
	    !_p11_rpc_message_read_space_string (msg, info->model, 16) ||
	    !_p11_rpc_message_read_space_string (msg, info->serialNumber, 16) ||
	    !_p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulMaxSessionCount) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulSessionCount) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulMaxRwSessionCount) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulRwSessionCount) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulMaxPinLen) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulMinPinLen) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulTotalPublicMemory) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulFreePublicMemory) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulTotalPrivateMemory) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulFreePrivateMemory) ||
	    !_p11_rpc_message_read_version (msg, &info->hardwareVersion) ||
	    !_p11_rpc_message_read_version (msg, &info->firmwareVersion) ||
	    !_p11_rpc_message_read_space_string (msg, info->utcTime, 16))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_mechanism_info (RpcMessage *msg,
                           CK_MECHANISM_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_read_ulong (msg, &info->ulMinKeySize) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulMaxKeySize) ||
	    !_p11_rpc_message_read_ulong (msg, &info->flags))
		return PARSE_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_sesssion_info (RpcMessage *msg,
                          CK_SESSION_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_read_ulong (msg, &info->slotID) ||
	    !_p11_rpc_message_read_ulong (msg, &info->state) ||
	    !_p11_rpc_message_read_ulong (msg, &info->flags) ||
	    !_p11_rpc_message_read_ulong (msg, &info->ulDeviceError))
		return PARSE_ERROR;

	return CKR_OK;
}

/* -------------------------------------------------------------------
 * CALL MACROS
 */

#define BEGIN_CALL_OR(call_id, module, if_no_daemon) \
	_p11_debug (#call_id ": enter"); \
	{ \
		RpcModule *_mod = module; RpcMessage _msg; \
		CK_RV _ret = call_prepare (_mod, &_msg, RPC_CALL_##call_id); \
		if (_ret == CKR_DEVICE_REMOVED) return (if_no_daemon); \
		if (_ret != CKR_OK) return _ret;

#define PROCESS_CALL \
		_ret = call_run (_mod, &_msg); \
		if (_ret != CKR_OK) goto _cleanup;

#define RETURN(ret) \
		_ret = ret; \
		goto _cleanup;

#define END_CALL \
	_cleanup: \
		_ret = call_done (_mod, &_msg, _ret); \
		_p11_debug ("ret: %d", _ret); \
		return _ret; \
	}

#define IN_BYTE(val) \
	if (!_p11_rpc_message_write_byte (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ULONG(val) \
	if (!_p11_rpc_message_write_ulong (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_STRING(val) \
	if (!_p11_rpc_message_write_zero_string (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_BYTE_BUFFER(arr, len) \
	if (len == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!_p11_rpc_message_write_byte_buffer (&_msg, arr ? *len : 0)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_BYTE_ARRAY(arr, len) \
	if (len != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!_p11_rpc_message_write_byte_array (&_msg, arr, len)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ULONG_BUFFER(arr, len) \
	if (len == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!_p11_rpc_message_write_ulong_buffer (&_msg, arr ? *len : 0)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ULONG_ARRAY(arr, len) \
	if (len != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; }\
	if (!_p11_rpc_message_write_ulong_array (&_msg, arr, len)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ATTRIBUTE_BUFFER(arr, num) \
	if (num != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!_p11_rpc_message_write_attribute_buffer (&_msg, (arr), (num))) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_ATTRIBUTE_ARRAY(arr, num) \
	if (num != 0 && arr == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	if (!_p11_rpc_message_write_attribute_array (&_msg, (arr), (num))) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_MECHANISM_TYPE(val) \
	if(!_p11_rpc_mechanism_is_supported (val)) \
		{ _ret = CKR_MECHANISM_INVALID; goto _cleanup; } \
	if (!_p11_rpc_message_write_ulong (&_msg, val)) \
		{ _ret = CKR_HOST_MEMORY; goto _cleanup; }

#define IN_MECHANISM(val) \
	if (val == NULL) \
		{ _ret = CKR_ARGUMENTS_BAD; goto _cleanup; } \
	_ret = proto_write_mechanism (&_msg, val); \
	if (_ret != CKR_OK) goto _cleanup;



#define OUT_ULONG(val) \
	if (val == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK && !_p11_rpc_message_read_ulong (&_msg, val)) \
		_ret = PARSE_ERROR;

#define OUT_BYTE_ARRAY(arr, len)  \
	if (len == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_byte_array (&_msg, (arr), (len), *(len));

#define OUT_ULONG_ARRAY(a, len) \
	if (len == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_ulong_array (&_msg, (a), (len), *(len));

#define OUT_ATTRIBUTE_ARRAY(arr, num) \
	if (_ret == CKR_OK) \
		_ret = proto_read_attribute_array (&_msg, (arr), (num));

#define OUT_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_info (&_msg, info);

#define OUT_SLOT_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_slot_info (&_msg, info);

#define OUT_TOKEN_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_token_info (&_msg, info);

#define OUT_SESSION_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_sesssion_info (&_msg, info);

#define OUT_MECHANISM_TYPE_ARRAY(arr, len) \
	if (len == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_ulong_array (&_msg, (arr), (len), *(len)); \
	if (_ret == CKR_OK && arr) \
		_p11_rpc_mechanism_list_purge (arr, len);

#define OUT_MECHANISM_INFO(info) \
	if (info == NULL) \
		_ret = CKR_ARGUMENTS_BAD; \
	if (_ret == CKR_OK) \
		_ret = proto_read_mechanism_info (&_msg, info);


/* -------------------------------------------------------------------
 * INITIALIZATION and 'GLOBAL' CALLS
 */

static CK_RV
rpc_C_Initialize (RpcModule *module,
                  CK_VOID_PTR init_args)
{
	CK_C_INITIALIZE_ARGS_PTR args = NULL;
	RpcSocket *socket = NULL;
	void *reserved = NULL;
	CK_RV ret = CKR_OK;
	RpcMessage msg;
	pid_t pid;

	assert (module != NULL);
	_p11_debug ("C_Initialize: enter");

	if (init_args != NULL) {
		int supplied_ok;

		/* pReserved must be NULL */
		args = init_args;

		/* ALL supplied function pointers need to have the value either NULL or non-NULL. */
		supplied_ok = (args->CreateMutex == NULL && args->DestroyMutex == NULL &&
		               args->LockMutex == NULL && args->UnlockMutex == NULL) ||
		              (args->CreateMutex != NULL && args->DestroyMutex != NULL &&
		               args->LockMutex != NULL && args->UnlockMutex != NULL);
		if (!supplied_ok) {
			_p11_message ("invalid set of mutex calls supplied");
			return CKR_ARGUMENTS_BAD;
		}

		/*
		 * When the CKF_OS_LOCKING_OK flag isn't set return an error.
		 * We must be able to use our pthread functionality.
		 */
		if (!(args->flags & CKF_OS_LOCKING_OK)) {
			_p11_message ("can't do without os locking");
			return CKR_CANT_LOCK;
		}

		if (args->pReserved)
			reserved = args->pReserved;
	}

	pthread_mutex_lock (&module->mutex);

	pid = getpid ();
	if (module->socket == NULL) {
		/* This process has called C_Initialize already */
		if (pid == module->initialized_pid) {
			_p11_message ("C_Initialize called twice for same process");
			ret = CKR_CRYPTOKI_ALREADY_INITIALIZED;
			goto done;
		}
	}

	/* Call out to initialize client callback */
	if (module->vtable->initialize) {
		ret = (module->vtable->initialize) (module->vtable->data, reserved, &socket);
		if (ret != CKR_OK)
			goto done;
		module->socket = socket;
	}

	if (module->socket == NULL) {
		ret = CKR_DEVICE_ERROR;
		goto done;
	}

	/* If we don't have read and write fds now, then initialize other side */
	ret = call_prepare (module, &msg, RPC_CALL_C_Initialize);
	if (ret == CKR_OK)
		if (!_p11_rpc_message_write_byte_array (&msg, RPC_HANDSHAKE, RPC_HANDSHAKE_LEN))
			ret = CKR_HOST_MEMORY;
	if (ret == CKR_OK)
		ret = call_run (module, &msg);
	call_done (module, &msg, ret);

done:
	/* Mark us as officially initialized */
	if (ret == CKR_OK) {
		module->initialized_pid = pid;

	} else if (ret != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		if (module->socket)
			_p11_rpc_socket_unref (module->socket);
		module->socket = NULL;
		module->initialized_pid = 0;
	}

	pthread_mutex_unlock (&module->mutex);

	_p11_debug ("C_Initialize: %d", ret);
	return ret;
}

static CK_RV
rpc_C_Finalize (RpcModule *module,
                CK_VOID_PTR reserved)
{
	CK_RV ret = CKR_OK;
	RpcMessage msg;

	_p11_debug ("C_Finalize: enter");
	return_val_if_fail (module->socket == NULL, CKR_CRYPTOKI_NOT_INITIALIZED);
	return_val_if_fail (!reserved, CKR_ARGUMENTS_BAD);

	pthread_mutex_lock (&module->mutex);

	ret = call_prepare (module, &msg, RPC_CALL_C_Finalize);
	if (ret == CKR_OK)
		ret = call_run (module, &msg);
	call_done (module, &msg, ret);
	if (ret != CKR_OK)
		_p11_message ("finalizing the daemon returned an error: %d", ret);

	/* This should stop all other calls in */
	_p11_rpc_socket_unref (module->socket);
	module->socket = NULL;
	module->initialized_pid = 0;

	pthread_mutex_unlock (&module->mutex);

	_p11_debug ("C_Finalize: %d", CKR_OK);

	/* We return okay anyway, meaning we are finalized */
	return CKR_OK;
}

static CK_RV
fill_stand_in_info (CK_INFO_PTR info)
{
	static CK_INFO stand_in_info = {
		{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
		"GNOME Keyring                   ",
		0,
		"GNOME Keyring (without daemon)  ",
		{ 1, 1 },
	};
	memcpy (info, &stand_in_info, sizeof (CK_INFO));
	return CKR_OK;

}

static CK_RV
rpc_C_GetInfo (RpcModule *module,
               CK_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetInfo, module, fill_stand_in_info (info));
	PROCESS_CALL;
		OUT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetFunctionList (RpcModule *module,
                       CK_FUNCTION_LIST_PTR_PTR list)
{
	return_val_if_fail (list != NULL, CKR_ARGUMENTS_BAD);
	*list = module->function_list;
	return CKR_OK;
}

static CK_RV
rpc_C_GetSlotList (RpcModule *module,
                   CK_BBOOL token_present,
                   CK_SLOT_ID_PTR slot_list,
                   CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetSlotList, module, (*count = 0, CKR_OK));
		IN_BYTE (token_present);
		IN_ULONG_BUFFER (slot_list, count);
	PROCESS_CALL;
		OUT_ULONG_ARRAY (slot_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotInfo (RpcModule *module,
                   CK_SLOT_ID slot_id,
                   CK_SLOT_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetSlotInfo, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
	PROCESS_CALL;
		OUT_SLOT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetTokenInfo (RpcModule *module,
                    CK_SLOT_ID slot_id,
                    CK_TOKEN_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetTokenInfo, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
	PROCESS_CALL;
		OUT_TOKEN_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismList (RpcModule *module,
                        CK_SLOT_ID slot_id,
                        CK_MECHANISM_TYPE_PTR mechanism_list,
                        CK_ULONG_PTR count)
{
	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetMechanismList, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_ULONG_BUFFER (mechanism_list, count);
	PROCESS_CALL;
		OUT_MECHANISM_TYPE_ARRAY (mechanism_list, count);
	END_CALL;

}

static CK_RV
rpc_C_GetMechanismInfo (RpcModule *module,
                        CK_SLOT_ID slot_id,
                        CK_MECHANISM_TYPE type,
                        CK_MECHANISM_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetMechanismInfo, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_MECHANISM_TYPE (type);
	PROCESS_CALL;
		OUT_MECHANISM_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitToken (RpcModule *module,
                 CK_SLOT_ID slot_id,
                 CK_UTF8CHAR_PTR pin, CK_ULONG pin_len,
                 CK_UTF8CHAR_PTR label)
{
	BEGIN_CALL_OR (C_InitToken, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_BYTE_ARRAY (pin, pin_len);
		IN_STRING (label);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_WaitForSlotEvent (RpcModule *module,
                        CK_FLAGS flags,
                        CK_SLOT_ID_PTR slot,
                        CK_VOID_PTR reserved)
{
	return_val_if_fail (slot, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_WaitForSlotEvent, module, CKR_DEVICE_REMOVED);
		IN_ULONG (flags);
	PROCESS_CALL;
		OUT_ULONG (slot);
	END_CALL;
}

static CK_RV
rpc_C_OpenSession (RpcModule *module,
                   CK_SLOT_ID slot_id,
                   CK_FLAGS flags,
                   CK_VOID_PTR user_data,
                   CK_NOTIFY callback,
                   CK_SESSION_HANDLE_PTR session)
{
	return_val_if_fail (session, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_OpenSession, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
		IN_ULONG (flags);
	PROCESS_CALL;
		OUT_ULONG (session);
	END_CALL;
}

static CK_RV
rpc_C_CloseSession (RpcModule *module,
                    CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_CloseSession, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_CloseAllSessions (RpcModule *module,
                        CK_SLOT_ID slot_id)
{
	BEGIN_CALL_OR (C_CloseAllSessions, module, CKR_SLOT_ID_INVALID);
		IN_ULONG (slot_id);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetFunctionStatus (RpcModule *module,
                         CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_GetFunctionStatus, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_CancelFunction (RpcModule *module,
                      CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_CancelFunction, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetSessionInfo (RpcModule *module,
                      CK_SESSION_HANDLE session,
                      CK_SESSION_INFO_PTR info)
{
	return_val_if_fail (info, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetSessionInfo, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
		OUT_SESSION_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitPIN (RpcModule *module,
               CK_SESSION_HANDLE session,
               CK_UTF8CHAR_PTR pin,
               CK_ULONG pin_len)
{
	BEGIN_CALL_OR (C_InitPIN, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SetPIN (RpcModule *module,
              CK_SESSION_HANDLE session,
              CK_UTF8CHAR_PTR old_pin,
              CK_ULONG old_pin_len,
              CK_UTF8CHAR_PTR new_pin,
              CK_ULONG new_pin_len)
{
	BEGIN_CALL_OR (C_SetPIN, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (old_pin, old_pin_len);
		IN_BYTE_ARRAY (new_pin, old_pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetOperationState (RpcModule *module,
                         CK_SESSION_HANDLE session,
                         CK_BYTE_PTR operation_state,
                         CK_ULONG_PTR operation_state_len)
{
	return_val_if_fail (operation_state_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetOperationState, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (operation_state, operation_state_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (operation_state, operation_state_len);
	END_CALL;
}

static CK_RV
rpc_C_SetOperationState (RpcModule *module,
                         CK_SESSION_HANDLE session,
                         CK_BYTE_PTR operation_state,
                         CK_ULONG operation_state_len,
                         CK_OBJECT_HANDLE encryption_key,
                         CK_OBJECT_HANDLE authentication_key)
{
	BEGIN_CALL_OR (C_SetOperationState, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (operation_state, operation_state_len);
		IN_ULONG (encryption_key);
		IN_ULONG (authentication_key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Login (RpcModule *module,
             CK_SESSION_HANDLE session,
             CK_USER_TYPE user_type,
             CK_UTF8CHAR_PTR pin,
             CK_ULONG pin_len)
{
	BEGIN_CALL_OR (C_Login, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (user_type);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Logout (RpcModule *module,
              CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_Logout, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_CreateObject (RpcModule *module,
                    CK_SESSION_HANDLE session,
                    CK_ATTRIBUTE_PTR template,
                    CK_ULONG count,
                    CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_CreateObject, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (new_object);
	END_CALL;
}

static CK_RV
rpc_C_CopyObject (RpcModule *module,
                  CK_SESSION_HANDLE session,
                  CK_OBJECT_HANDLE object,
                  CK_ATTRIBUTE_PTR template,
                  CK_ULONG count,
                  CK_OBJECT_HANDLE_PTR new_object)
{
	return_val_if_fail (new_object, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_CopyObject, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (new_object);
	END_CALL;
}


static CK_RV
rpc_C_DestroyObject (RpcModule *module,
                     CK_SESSION_HANDLE session,
                     CK_OBJECT_HANDLE object)
{
	BEGIN_CALL_OR (C_DestroyObject, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GetObjectSize (RpcModule *module,
                     CK_SESSION_HANDLE session,
                     CK_OBJECT_HANDLE object,
                     CK_ULONG_PTR size)
{
	return_val_if_fail (size, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_GetObjectSize, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL;
		OUT_ULONG (size);
	END_CALL;
}

static CK_RV
rpc_C_GetAttributeValue (RpcModule *module,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	BEGIN_CALL_OR (C_GetAttributeValue, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_BUFFER (template, count);
	PROCESS_CALL;
		OUT_ATTRIBUTE_ARRAY (template, count);
	END_CALL;
}

static CK_RV
rpc_C_SetAttributeValue (RpcModule *module,
                         CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
                         CK_ATTRIBUTE_PTR template,
                         CK_ULONG count)
{
	BEGIN_CALL_OR (C_SetAttributeValue, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsInit (RpcModule *module,
                       CK_SESSION_HANDLE session,
                       CK_ATTRIBUTE_PTR template,
                       CK_ULONG count)
{
	BEGIN_CALL_OR (C_FindObjectsInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_FindObjects (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_OBJECT_HANDLE_PTR objects,
                   CK_ULONG max_count,
                   CK_ULONG_PTR count)
{
	/* HACK: To fix a stupid gcc warning */
	CK_ULONG_PTR address_of_max_count = &max_count;

	return_val_if_fail (count, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_FindObjects, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG_BUFFER (objects, address_of_max_count);
	PROCESS_CALL;
		*count = max_count;
		OUT_ULONG_ARRAY (objects, count);
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsFinal (RpcModule *module,
                        CK_SESSION_HANDLE session)
{
	BEGIN_CALL_OR (C_FindObjectsFinal, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_EncryptInit (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_EncryptInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Encrypt (RpcModule *module,
               CK_SESSION_HANDLE session,
               CK_BYTE_PTR data,
               CK_ULONG data_len,
               CK_BYTE_PTR encrypted_data,
               CK_ULONG_PTR encrypted_data_len)
{
	return_val_if_fail (encrypted_data_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Encrypt, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (encrypted_data, encrypted_data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (encrypted_data, encrypted_data_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptUpdate (RpcModule *module,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR part,
                     CK_ULONG part_len,
                     CK_BYTE_PTR encrypted_part,
                     CK_ULONG_PTR encrypted_part_len)
{
	return_val_if_fail (encrypted_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_EncryptUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptFinal (RpcModule *module,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_EncryptFinal, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_part, last_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (last_part, last_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptInit (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_DecryptInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Decrypt (RpcModule *module,
               CK_SESSION_HANDLE session,
               CK_BYTE_PTR enc_data,
               CK_ULONG enc_data_len,
               CK_BYTE_PTR data,
               CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Decrypt, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_data, enc_data_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptUpdate (RpcModule *module,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR enc_part,
                     CK_ULONG enc_part_len,
                     CK_BYTE_PTR part,
                     CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptFinal (RpcModule *module,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR last_part,
                    CK_ULONG_PTR last_part_len)
{
	return_val_if_fail (last_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptFinal, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_part, last_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (last_part, last_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestInit (RpcModule *module,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism)
{
	BEGIN_CALL_OR (C_DigestInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Digest (RpcModule *module,
              CK_SESSION_HANDLE session,
              CK_BYTE_PTR data,
              CK_ULONG data_len,
              CK_BYTE_PTR digest,
              CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Digest, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestUpdate (RpcModule *module,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR part,
                    CK_ULONG part_len)
{
	BEGIN_CALL_OR (C_DigestUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_DigestKey (RpcModule *module,
                 CK_SESSION_HANDLE session,
                 CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_DigestKey, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_DigestFinal (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR digest,
                   CK_ULONG_PTR digest_len)
{
	return_val_if_fail (digest_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DigestFinal, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_SignInit (RpcModule *module,
                CK_SESSION_HANDLE session,
                CK_MECHANISM_PTR mechanism,
                CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_SignInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Sign (RpcModule *module,
            CK_SESSION_HANDLE session,
            CK_BYTE_PTR data,
            CK_ULONG data_len,
            CK_BYTE_PTR signature,
            CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_Sign, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignUpdate (RpcModule *module,
                  CK_SESSION_HANDLE session,
                  CK_BYTE_PTR part,
                  CK_ULONG part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SignFinal (RpcModule *module,
                 CK_SESSION_HANDLE session,
                 CK_BYTE_PTR signature,
                 CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignFinal, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignRecoverInit (RpcModule *module,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_SignRecoverInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_SignRecover (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR data,
                   CK_ULONG data_len,
                   CK_BYTE_PTR signature, CK_ULONG_PTR signature_len)
{
	return_val_if_fail (signature_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignRecover, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_VerifyInit (RpcModule *module,
                  CK_SESSION_HANDLE session,
                  CK_MECHANISM_PTR mechanism,
                  CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_VerifyInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_Verify (RpcModule *module,
              CK_SESSION_HANDLE session,
              CK_BYTE_PTR data,
              CK_ULONG data_len,
              CK_BYTE_PTR signature,
              CK_ULONG signature_len)
{
	BEGIN_CALL_OR (C_Verify, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyUpdate (RpcModule *module,
                    CK_SESSION_HANDLE session,
                    CK_BYTE_PTR part,
                    CK_ULONG part_len)
{
	BEGIN_CALL_OR (C_VerifyUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyFinal (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_BYTE_PTR signature,
                   CK_ULONG signature_len)
{
	BEGIN_CALL_OR (C_VerifyFinal, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecoverInit (RpcModule *module,
                         CK_SESSION_HANDLE session,
                         CK_MECHANISM_PTR mechanism,
                         CK_OBJECT_HANDLE key)
{
	BEGIN_CALL_OR (C_VerifyRecoverInit, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecover (RpcModule *module,
                     CK_SESSION_HANDLE session,
                     CK_BYTE_PTR signature,
                     CK_ULONG signature_len,
                     CK_BYTE_PTR data,
                     CK_ULONG_PTR data_len)
{
	return_val_if_fail (data_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_VerifyRecover, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestEncryptUpdate (RpcModule *module,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR part,
                           CK_ULONG part_len,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DigestEncryptUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (enc_part, enc_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptDigestUpdate (RpcModule *module,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG enc_part_len,
                           CK_BYTE_PTR part,
                           CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptDigestUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_SignEncryptUpdate (RpcModule *module,
                         CK_SESSION_HANDLE session,
                         CK_BYTE_PTR part,
                         CK_ULONG part_len,
                         CK_BYTE_PTR enc_part,
                         CK_ULONG_PTR enc_part_len)
{
	return_val_if_fail (enc_part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_SignEncryptUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (enc_part, enc_part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (enc_part, enc_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptVerifyUpdate (RpcModule *module,
                           CK_SESSION_HANDLE session,
                           CK_BYTE_PTR enc_part,
                           CK_ULONG enc_part_len,
                           CK_BYTE_PTR part,
                           CK_ULONG_PTR part_len)
{
	return_val_if_fail (part_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_DecryptVerifyUpdate, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (enc_part, enc_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKey (RpcModule *module,
                   CK_SESSION_HANDLE session,
                   CK_MECHANISM_PTR mechanism,
                   CK_ATTRIBUTE_PTR template,
                   CK_ULONG count,
                   CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL_OR (C_GenerateKey, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKeyPair (RpcModule *module,
                       CK_SESSION_HANDLE session,
                       CK_MECHANISM_PTR mechanism,
                       CK_ATTRIBUTE_PTR pub_template,
                       CK_ULONG pub_count,
                       CK_ATTRIBUTE_PTR priv_template,
                       CK_ULONG priv_count,
                       CK_OBJECT_HANDLE_PTR pub_key,
                       CK_OBJECT_HANDLE_PTR priv_key)
{
	BEGIN_CALL_OR (C_GenerateKeyPair, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (pub_template, pub_count);
		IN_ATTRIBUTE_ARRAY (priv_template, priv_count);
	PROCESS_CALL;
		OUT_ULONG (pub_key);
		OUT_ULONG (priv_key);
	END_CALL;
}

static CK_RV
rpc_C_WrapKey (RpcModule *module,
               CK_SESSION_HANDLE session,
               CK_MECHANISM_PTR mechanism,
               CK_OBJECT_HANDLE wrapping_key,
               CK_OBJECT_HANDLE key,
               CK_BYTE_PTR wrapped_key,
               CK_ULONG_PTR wrapped_key_len)
{
	return_val_if_fail (wrapped_key_len, CKR_ARGUMENTS_BAD);

	BEGIN_CALL_OR (C_WrapKey, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (wrapping_key);
		IN_ULONG (key);
		IN_BYTE_BUFFER (wrapped_key, wrapped_key_len);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (wrapped_key, wrapped_key_len);
	END_CALL;
}

static CK_RV
rpc_C_UnwrapKey (RpcModule *module,
                 CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE unwrapping_key,
                 CK_BYTE_PTR wrapped_key,
                 CK_ULONG wrapped_key_len,
                 CK_ATTRIBUTE_PTR template,
                 CK_ULONG count,
                 CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL_OR (C_UnwrapKey, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (unwrapping_key);
		IN_BYTE_ARRAY (wrapped_key, wrapped_key_len);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_DeriveKey (RpcModule *module,
                 CK_SESSION_HANDLE session,
                 CK_MECHANISM_PTR mechanism,
                 CK_OBJECT_HANDLE base_key,
                 CK_ATTRIBUTE_PTR template,
                 CK_ULONG count,
                 CK_OBJECT_HANDLE_PTR key)
{
	BEGIN_CALL_OR (C_DeriveKey, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (base_key);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL;
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_SeedRandom (RpcModule *module,
                  CK_SESSION_HANDLE session,
                  CK_BYTE_PTR seed,
                  CK_ULONG seed_len)
{
	BEGIN_CALL_OR (C_SeedRandom, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_ARRAY (seed, seed_len);
	PROCESS_CALL;
	END_CALL;
}

static CK_RV
rpc_C_GenerateRandom (RpcModule *module,
                      CK_SESSION_HANDLE session,
                      CK_BYTE_PTR random_data,
                      CK_ULONG random_len)
{
	CK_ULONG_PTR address = &random_len;
	BEGIN_CALL_OR (C_GenerateRandom, module, CKR_SESSION_HANDLE_INVALID);
		IN_ULONG (session);
		IN_BYTE_BUFFER (random_data, address);
	PROCESS_CALL;
		OUT_BYTE_ARRAY (random_data, address);
	END_CALL;
}

/*
 * This macro defines an RPC PKCS#11 module.
 *
 * Sadly PKCS#11 is not fully OOP does not pass the pointer to the module to
 * each module function. Thus we have to define different functions for each
 * RPC module which "know" which module they belong to.
 *
 * This macro defines PKCS#11 functions and function list which pass their
 * RpcModule to the actual implementation functions above.
 */

#define RPC_DEFINE_MODULE(id) \
	static RpcModule rpc_module_##id; \
	static CK_RV rpc_C_Initialize_##id (CK_VOID_PTR init_args) \
		{ return rpc_C_Initialize (&rpc_module_##id, init_args); } \
	static CK_RV rpc_C_Finalize_##id (CK_VOID_PTR reserved) \
		{ return rpc_C_Finalize (&rpc_module_##id, reserved); } \
	static CK_RV rpc_C_GetInfo_##id (CK_INFO_PTR info) \
		{ return rpc_C_GetInfo (&rpc_module_##id, info); } \
	static CK_RV rpc_C_GetFunctionList_##id (CK_FUNCTION_LIST_PTR_PTR list) \
		{ return rpc_C_GetFunctionList (&rpc_module_##id, list); } \
	static CK_RV rpc_C_GetSlotList_##id (CK_BBOOL token_present, CK_SLOT_ID_PTR slot_list, CK_ULONG_PTR count) \
		{ return rpc_C_GetSlotList (&rpc_module_##id, token_present, slot_list, count); } \
	static CK_RV rpc_C_GetSlotInfo_##id (CK_SLOT_ID slot_id, CK_SLOT_INFO_PTR info) \
		{ return rpc_C_GetSlotInfo (&rpc_module_##id, slot_id, info); } \
	static CK_RV rpc_C_GetTokenInfo_##id (CK_SLOT_ID slot_id, CK_TOKEN_INFO_PTR info) \
		{ return rpc_C_GetTokenInfo (&rpc_module_##id, slot_id, info); } \
	static CK_RV rpc_C_GetMechanismList_##id (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE_PTR mechanism_list, CK_ULONG_PTR count) \
		{ return rpc_C_GetMechanismList (&rpc_module_##id, slot_id, mechanism_list, count); } \
	static CK_RV rpc_C_GetMechanismInfo_##id (CK_SLOT_ID slot_id, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR info) \
		{ return rpc_C_GetMechanismInfo (&rpc_module_##id, slot_id, type, info); } \
	static CK_RV rpc_C_InitToken_##id (CK_SLOT_ID slot_id, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len, CK_UTF8CHAR_PTR label) \
		{ return rpc_C_InitToken (&rpc_module_##id, slot_id, pin, pin_len, label); } \
	static CK_RV rpc_C_WaitForSlotEvent_##id (CK_FLAGS flags, CK_SLOT_ID_PTR slot, CK_VOID_PTR reserved) \
		{ return rpc_C_WaitForSlotEvent (&rpc_module_##id, flags, slot, reserved); } \
	static CK_RV rpc_C_OpenSession_##id (CK_SLOT_ID slot_id, CK_FLAGS flags, CK_VOID_PTR user_data, CK_NOTIFY callback, CK_SESSION_HANDLE_PTR session) \
		{ return rpc_C_OpenSession (&rpc_module_##id, slot_id, flags, user_data, callback, session); } \
	static CK_RV rpc_C_CloseSession_##id (CK_SESSION_HANDLE session) \
		{ return rpc_C_CloseSession (&rpc_module_##id, session); } \
	static CK_RV rpc_C_CloseAllSessions_##id (CK_SLOT_ID slot_id) \
		{ return rpc_C_CloseAllSessions (&rpc_module_##id, slot_id); } \
	static CK_RV rpc_C_GetFunctionStatus_##id (CK_SESSION_HANDLE session) \
		{ return rpc_C_GetFunctionStatus (&rpc_module_##id, session); } \
	static CK_RV rpc_C_CancelFunction_##id (CK_SESSION_HANDLE session) \
		{ return rpc_C_CancelFunction (&rpc_module_##id, session); } \
	static CK_RV rpc_C_GetSessionInfo_##id (CK_SESSION_HANDLE session, CK_SESSION_INFO_PTR info) \
		{ return rpc_C_GetSessionInfo (&rpc_module_##id, session, info); } \
	static CK_RV rpc_C_InitPIN_##id (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) \
		{ return rpc_C_InitPIN (&rpc_module_##id, session, pin, pin_len); } \
	static CK_RV rpc_C_SetPIN_##id (CK_SESSION_HANDLE session, CK_UTF8CHAR_PTR old_pin, CK_ULONG old_pin_len, CK_UTF8CHAR_PTR new_pin, CK_ULONG new_pin_len) \
		{ return rpc_C_SetPIN (&rpc_module_##id, session, old_pin, old_pin_len, new_pin, new_pin_len); } \
	static CK_RV rpc_C_GetOperationState_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state, CK_ULONG_PTR operation_state_len) \
		{ return rpc_C_GetOperationState (&rpc_module_##id, session, operation_state, operation_state_len); } \
	static CK_RV rpc_C_SetOperationState_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR operation_state, CK_ULONG operation_state_len, CK_OBJECT_HANDLE encryption_key, CK_OBJECT_HANDLE authentication_key) \
		{ return rpc_C_SetOperationState (&rpc_module_##id, session, operation_state, operation_state_len, encryption_key, authentication_key); } \
	static CK_RV rpc_C_Login_##id (CK_SESSION_HANDLE session, CK_USER_TYPE user_type, CK_UTF8CHAR_PTR pin, CK_ULONG pin_len) \
		{ return rpc_C_Login (&rpc_module_##id, session, user_type, pin, pin_len); } \
	static CK_RV rpc_C_Logout_##id (CK_SESSION_HANDLE session) \
		{ return rpc_C_Logout (&rpc_module_##id, session); } \
	static CK_RV rpc_C_CreateObject_##id (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object) \
		{ return rpc_C_CreateObject (&rpc_module_##id, session, template, count, new_object); } \
	static CK_RV rpc_C_CopyObject_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR new_object) \
		{ return rpc_C_CopyObject (&rpc_module_##id, session, object, template, count, new_object); } \
	static CK_RV rpc_C_DestroyObject_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object) \
		{ return rpc_C_DestroyObject (&rpc_module_##id, session, object); } \
	static CK_RV rpc_C_GetObjectSize_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ULONG_PTR size) \
		{ return rpc_C_GetObjectSize (&rpc_module_##id, session, object, size); } \
	static CK_RV rpc_C_GetAttributeValue_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count) \
		{ return rpc_C_GetAttributeValue (&rpc_module_##id, session, object, template, count); } \
	static CK_RV rpc_C_SetAttributeValue_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object, CK_ATTRIBUTE_PTR template, CK_ULONG count) \
		{ return rpc_C_SetAttributeValue (&rpc_module_##id, session, object, template, count); } \
	static CK_RV rpc_C_FindObjectsInit_##id (CK_SESSION_HANDLE session, CK_ATTRIBUTE_PTR template, CK_ULONG count) \
		{ return rpc_C_FindObjectsInit (&rpc_module_##id, session, template, count); } \
	static CK_RV rpc_C_FindObjects_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE_PTR objects, CK_ULONG max_count, CK_ULONG_PTR count) \
		{ return rpc_C_FindObjects (&rpc_module_##id, session, objects, max_count, count); } \
	static CK_RV rpc_C_FindObjectsFinal_##id (CK_SESSION_HANDLE session) \
		{ return rpc_C_FindObjectsFinal (&rpc_module_##id, session); } \
	static CK_RV rpc_C_EncryptInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) \
		{ return rpc_C_EncryptInit (&rpc_module_##id, session, mechanism, key); } \
	static CK_RV rpc_C_Encrypt_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR encrypted_data, CK_ULONG_PTR encrypted_data_len) \
		{ return rpc_C_Encrypt (&rpc_module_##id, session, data, data_len, encrypted_data, encrypted_data_len); } \
	static CK_RV rpc_C_EncryptUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR encrypted_part, CK_ULONG_PTR encrypted_part_len) \
		{ return rpc_C_EncryptUpdate (&rpc_module_##id, session, part, part_len, encrypted_part, encrypted_part_len); } \
	static CK_RV rpc_C_EncryptFinal_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) \
		{ return rpc_C_EncryptFinal (&rpc_module_##id, session, last_part, last_part_len); } \
	static CK_RV rpc_C_DecryptInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) \
		{ return rpc_C_DecryptInit (&rpc_module_##id, session, mechanism, key); } \
	static CK_RV rpc_C_Decrypt_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_data, CK_ULONG enc_data_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) \
		{ return rpc_C_Decrypt (&rpc_module_##id, session, enc_data, enc_data_len, data, data_len); } \
	static CK_RV rpc_C_DecryptUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_part, CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) \
		{ return rpc_C_DecryptUpdate (&rpc_module_##id, session, enc_part, enc_part_len, part, part_len); } \
	static CK_RV rpc_C_DecryptFinal_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR last_part, CK_ULONG_PTR last_part_len) \
		{ return rpc_C_DecryptFinal (&rpc_module_##id, session, last_part, last_part_len); } \
	static CK_RV rpc_C_DigestInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism) \
		{ return rpc_C_DigestInit (&rpc_module_##id, session, mechanism); } \
	static CK_RV rpc_C_Digest_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) \
		{ return rpc_C_Digest (&rpc_module_##id, session, data, data_len, digest, digest_len); } \
	static CK_RV rpc_C_DigestUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len) \
		{ return rpc_C_DigestUpdate (&rpc_module_##id, session, part, part_len); } \
	static CK_RV rpc_C_DigestKey_##id (CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) \
		{ return rpc_C_DigestKey (&rpc_module_##id, session, key); } \
	static CK_RV rpc_C_DigestFinal_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR digest, CK_ULONG_PTR digest_len) \
		{ return rpc_C_DigestFinal (&rpc_module_##id, session, digest, digest_len); } \
	static CK_RV rpc_C_SignInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) \
		{ return rpc_C_SignInit (&rpc_module_##id, session, mechanism, key); } \
	static CK_RV rpc_C_Sign_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) \
		{ return rpc_C_Sign (&rpc_module_##id, session, data, data_len, signature, signature_len); } \
	static CK_RV rpc_C_SignUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len) \
		{ return rpc_C_SignUpdate (&rpc_module_##id, session, part, part_len); } \
	static CK_RV rpc_C_SignFinal_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) \
		{ return rpc_C_SignFinal (&rpc_module_##id, session, signature, signature_len); } \
	static CK_RV rpc_C_SignRecoverInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) \
		{ return rpc_C_SignRecoverInit (&rpc_module_##id, session, mechanism, key); } \
	static CK_RV rpc_C_SignRecover_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG_PTR signature_len) \
		{ return rpc_C_SignRecover (&rpc_module_##id, session, data, data_len, signature, signature_len); } \
	static CK_RV rpc_C_VerifyInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) \
		{ return rpc_C_VerifyInit (&rpc_module_##id, session, mechanism, key); } \
	static CK_RV rpc_C_Verify_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG data_len, CK_BYTE_PTR signature, CK_ULONG signature_len) \
		{ return rpc_C_Verify (&rpc_module_##id, session, data, data_len, signature, signature_len); } \
	static CK_RV rpc_C_VerifyUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len) \
		{ return rpc_C_VerifyUpdate (&rpc_module_##id, session, part, part_len); } \
	static CK_RV rpc_C_VerifyFinal_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR signature, CK_ULONG signature_len) \
		{ return rpc_C_VerifyFinal (&rpc_module_##id, session, signature, signature_len); } \
	static CK_RV rpc_C_VerifyRecoverInit_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) \
		{ return rpc_C_VerifyRecoverInit (&rpc_module_##id, session, mechanism, key); } \
	static CK_RV rpc_C_VerifyRecover_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR signature, CK_ULONG signature_len, CK_BYTE_PTR data, CK_ULONG_PTR data_len) \
		{ return rpc_C_VerifyRecover (&rpc_module_##id, session, signature, signature_len, data, data_len); } \
	static CK_RV rpc_C_DigestEncryptUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc_part, CK_ULONG_PTR enc_part_len) \
		{ return rpc_C_DigestEncryptUpdate (&rpc_module_##id, session, part, part_len, enc_part, enc_part_len); } \
	static CK_RV rpc_C_DecryptDigestUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_part, CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) \
		{ return rpc_C_DecryptDigestUpdate (&rpc_module_##id, session, enc_part, enc_part_len, part, part_len); } \
	static CK_RV rpc_C_SignEncryptUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR part, CK_ULONG part_len, CK_BYTE_PTR enc_part, CK_ULONG_PTR enc_part_len) \
		{ return rpc_C_SignEncryptUpdate (&rpc_module_##id, session, part, part_len, enc_part, enc_part_len); } \
	static CK_RV rpc_C_DecryptVerifyUpdate_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR enc_part, CK_ULONG enc_part_len, CK_BYTE_PTR part, CK_ULONG_PTR part_len) \
		{ return rpc_C_DecryptVerifyUpdate (&rpc_module_##id, session, enc_part, enc_part_len, part, part_len); } \
	static CK_RV rpc_C_GenerateKey_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) \
		{ return rpc_C_GenerateKey (&rpc_module_##id, session, mechanism, template, count, key); } \
	static CK_RV rpc_C_GenerateKeyPair_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_ATTRIBUTE_PTR pub_template, CK_ULONG pub_count, CK_ATTRIBUTE_PTR priv_template, CK_ULONG priv_count, CK_OBJECT_HANDLE_PTR pub_key, CK_OBJECT_HANDLE_PTR priv_key) \
		{ return rpc_C_GenerateKeyPair (&rpc_module_##id, session, mechanism, pub_template, pub_count, priv_template, priv_count, pub_key, priv_key); } \
	static CK_RV rpc_C_WrapKey_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key, CK_ULONG_PTR wrapped_key_len) \
		{ return rpc_C_WrapKey (&rpc_module_##id, session, mechanism, wrapping_key, key, wrapped_key, wrapped_key_len); } \
	static CK_RV rpc_C_UnwrapKey_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE unwrapping_key, CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) \
		{ return rpc_C_UnwrapKey (&rpc_module_##id, session, mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, count, key); } \
	static CK_RV rpc_C_DeriveKey_##id (CK_SESSION_HANDLE session, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE base_key, CK_ATTRIBUTE_PTR template, CK_ULONG count, CK_OBJECT_HANDLE_PTR key) \
		{ return rpc_C_DeriveKey (&rpc_module_##id, session, mechanism, base_key, template, count, key); } \
	static CK_RV rpc_C_SeedRandom_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR seed, CK_ULONG seed_len) \
		{ return rpc_C_SeedRandom (&rpc_module_##id, session, seed, seed_len); } \
	static CK_RV rpc_C_GenerateRandom_##id (CK_SESSION_HANDLE session, CK_BYTE_PTR random_data, CK_ULONG random_len) \
		{ return rpc_C_GenerateRandom (&rpc_module_##id, session, random_data, random_len); } \
	static const CK_FUNCTION_LIST rpc_function_list##id = { { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR }, \
		rpc_C_Initialize_##id, rpc_C_Finalize_##id, rpc_C_GetInfo_##id, rpc_C_GetFunctionList_##id, \
		rpc_C_GetSlotList_##id, rpc_C_GetSlotInfo_##id, rpc_C_GetTokenInfo_##id, rpc_C_GetMechanismList_##id, \
		rpc_C_GetMechanismInfo_##id, rpc_C_InitToken_##id, rpc_C_InitPIN_##id, rpc_C_SetPIN_##id, \
		rpc_C_OpenSession_##id, rpc_C_CloseSession_##id, rpc_C_CloseAllSessions_##id, rpc_C_GetSessionInfo_##id, \
		rpc_C_GetOperationState_##id, rpc_C_SetOperationState_##id, rpc_C_Login_##id, rpc_C_Logout_##id, \
		rpc_C_CreateObject_##id, rpc_C_CopyObject_##id, rpc_C_DestroyObject_##id, rpc_C_GetObjectSize_##id, \
		rpc_C_GetAttributeValue_##id, rpc_C_SetAttributeValue_##id, rpc_C_FindObjectsInit_##id, \
		rpc_C_FindObjects_##id, rpc_C_FindObjectsFinal_##id, rpc_C_EncryptInit_##id, rpc_C_Encrypt_##id, \
		rpc_C_EncryptUpdate_##id, rpc_C_EncryptFinal_##id, rpc_C_DecryptInit_##id, rpc_C_Decrypt_##id, \
		rpc_C_DecryptUpdate_##id, rpc_C_DecryptFinal_##id, rpc_C_DigestInit_##id, rpc_C_Digest_##id, \
		rpc_C_DigestUpdate_##id, rpc_C_DigestKey_##id, rpc_C_DigestFinal_##id, rpc_C_SignInit_##id, \
		rpc_C_Sign_##id, rpc_C_SignUpdate_##id, rpc_C_SignFinal_##id, rpc_C_SignRecoverInit_##id, \
		rpc_C_SignRecover_##id, rpc_C_VerifyInit_##id, rpc_C_Verify_##id, rpc_C_VerifyUpdate_##id, \
		rpc_C_VerifyFinal_##id, rpc_C_VerifyRecoverInit_##id, rpc_C_VerifyRecover_##id, rpc_C_DigestEncryptUpdate_##id, \
		rpc_C_DecryptDigestUpdate_##id, rpc_C_SignEncryptUpdate_##id, rpc_C_DecryptVerifyUpdate_##id, \
		rpc_C_GenerateKey_##id, rpc_C_GenerateKeyPair_##id, rpc_C_WrapKey_##id, rpc_C_UnwrapKey_##id, \
		rpc_C_DeriveKey_##id, rpc_C_SeedRandom_##id, rpc_C_GenerateRandom_##id, rpc_C_GetFunctionStatus_##id, \
		rpc_C_CancelFunction_##id, rpc_C_WaitForSlotEvent_##id, }; \
	static RpcModule rpc_module_##id = RPC_MODULE_INIT (id, &rpc_function_list##id);

/*
 * This macro is to save typing in the two definitions below.
 * RPC_MODULE is redefined as needed below. The numbers must be sequential.
 */
#define RPC_MODULE_ELEMENTS \
	RPC_MODULE (0) RPC_MODULE (1) RPC_MODULE (2) RPC_MODULE (3) RPC_MODULE (4) \
	RPC_MODULE (5) RPC_MODULE (6) RPC_MODULE (7) RPC_MODULE (8) RPC_MODULE (9) \
	RPC_MODULE (10) RPC_MODULE (11) RPC_MODULE (12) RPC_MODULE (13) RPC_MODULE (14) \
	RPC_MODULE (15) RPC_MODULE (16) RPC_MODULE (17) RPC_MODULE (18) RPC_MODULE (19) \
	RPC_MODULE (20) RPC_MODULE (21) RPC_MODULE (22) RPC_MODULE (23) RPC_MODULE (24) \
	RPC_MODULE (25) RPC_MODULE (26) RPC_MODULE (27) RPC_MODULE (28) RPC_MODULE (29) \
	RPC_MODULE (30) RPC_MODULE (31) RPC_MODULE (32)

/*
 * Use RPC_DEFINE_MODULE to define all the RPC functions and function lists
 * for each module.
 */
#define RPC_MODULE(id) RPC_DEFINE_MODULE (id)
RPC_MODULE_ELEMENTS
#undef RPC_MODULE

/* Now init the array of modules */
static RpcModule *RPC_MODULES[] = {
	#define RPC_MODULE(id) &rpc_module_##id,
	#undef RPC_MODULE
};

#define N_RPC_MODULES \
	sizeof (RPC_MODULES) / sizeof (RPC_MODULES[0])

CK_FUNCTION_LIST_PTR
_p11_rpc_client_register (const RpcClientVtable *vtable)
{
	static pthread_mutex_t register_mutex = PTHREAD_MUTEX_INITIALIZER;
	CK_FUNCTION_LIST_PTR function_list = NULL;
	int i;

	assert (vtable != NULL);
	RPC_CHECK_CALLS ();

	pthread_mutex_lock (&register_mutex);

	/* Find an rpc module function list that's free */
	for (i = 0; i < N_RPC_MODULES; i++) {
		assert (RPC_MODULES[i]->check == i);
		if (RPC_MODULES[i]->vtable == NULL) {
			RPC_MODULES[i]->vtable = vtable;
			function_list = RPC_MODULES[i]->function_list;
			assert (function_list != NULL);
			break;
		}
	}

	pthread_mutex_unlock (&register_mutex);

	if (function_list == NULL)
		_p11_message ("too many rpc client modules: %d", N_RPC_MODULES);

	return function_list;
}
