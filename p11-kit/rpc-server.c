/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* rpc-dispatch.h - receiver of our PKCS#11 protocol.

   Copyright (C) 2008, Stef Walter
   Copyright (C) 2012, Stef Walter

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

   Author: Stef Walter <stef@thewalter.net>
*/

#include "config.h"

#define DEBUG_FLAG DEBUG_RPC
#include "debug.h"
#include "pkcs11.h"
#include "private.h"
#include "rpc-message.h"
#include "rpc-server.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The error returned on protocol failures */
#define PARSE_ERROR CKR_DEVICE_ERROR
#define PREP_ERROR  CKR_DEVICE_MEMORY

#define return_val_if_fail(x, v) \
	if (!(x)) { _p11_message ("'%s' not true at %s", #x, __func__); return v; }

/* Allocator for call session buffers */
static void *
log_allocator (void *pointer,
               size_t size)
{
	void *result = realloc (pointer, (size_t)size);
	if (!result && size)
		_p11_message ("memory allocation of %lu bytes failed", size);
	return result;
}

static CK_RV
proto_read_byte_buffer (RpcMessage *msg,
                        CK_BYTE_PTR *buffer,
                        CK_ULONG *n_buffer)
{
	uint32_t length;

	assert (msg != NULL);
	assert (buffer != NULL);
	assert (n_buffer != NULL);

	/* Check that we're supposed to be reading this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "fy"));

	/* The number of ulongs there's room for on the other end */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &length))
		return PARSE_ERROR;

	*n_buffer = length;
	*buffer = NULL;

	/* If set to zero, then they just want the length */
	if (length == 0)
		return CKR_OK;

	*buffer = _p11_rpc_message_alloc_extra (msg, length * sizeof (CK_BYTE));
	if (*buffer == NULL)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_read_byte_array (RpcMessage *msg,
                       CK_BYTE_PTR *array,
                       CK_ULONG *n_array)
{
	const unsigned char *data;
	unsigned char valid;
	size_t n_data;

	assert (msg != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "ay"));

	/* Read out the byte which says whether data is present or not */
	if (!_p11_buffer_get_byte (&msg->buffer, msg->parsed, &msg->parsed, &valid))
		return PARSE_ERROR;

	if (!valid) {
		*array = NULL;
		*n_array = 0;
		return CKR_OK;
	}

	/* Point our arguments into the buffer */
	if (!_p11_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed,
	                                 &data, &n_data))
		return PARSE_ERROR;

	*array = (CK_BYTE_PTR)data;
	*n_array = n_data;
	return CKR_OK;
}

static CK_RV
proto_write_byte_array (RpcMessage *msg,
                        CK_BYTE_PTR array,
                        CK_ULONG len,
                        CK_RV ret)
{
	assert (msg != NULL);

	/*
	 * When returning an byte array, in many cases we need to pass
	 * an invalid array along with a length, which signifies CKR_BUFFER_TOO_SMALL.
	 */

	switch (ret) {
	case CKR_BUFFER_TOO_SMALL:
		array = NULL;
		/* fall through */
	case CKR_OK:
		break;

	/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!_p11_rpc_message_write_byte_array (msg, array, len))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_ulong_buffer (RpcMessage *msg,
                         CK_ULONG_PTR *buffer,
                         CK_ULONG *n_buffer)
{
	uint32_t length;

	assert (msg != NULL);
	assert (buffer != NULL);
	assert (n_buffer != NULL);

	/* Check that we're supposed to be reading this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "fu"));

	/* The number of ulongs there's room for on the other end */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &length))
		return PARSE_ERROR;

	*n_buffer = length;
	*buffer = NULL;

	/* If set to zero, then they just want the length */
	if (length == 0)
		return CKR_OK;

	*buffer = _p11_rpc_message_alloc_extra (msg, length * sizeof (CK_ULONG));
	if (!*buffer)
		return CKR_DEVICE_MEMORY;

	return CKR_OK;
}

static CK_RV
proto_write_ulong_array (RpcMessage *msg,
                         CK_ULONG_PTR array,
                         CK_ULONG len,
                         CK_RV ret)
{
	assert (msg != NULL);

	/*
	 * When returning an ulong array, in many cases we need to pass
	 * an invalid array along with a length, which signifies CKR_BUFFER_TOO_SMALL.
	 */

	switch (ret) {
	case CKR_BUFFER_TOO_SMALL:
		array = NULL;
		/* fall through */
	case CKR_OK:
		break;

	/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!_p11_rpc_message_write_ulong_array (msg, array, len))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_attribute_buffer (RpcMessage *msg,
                             CK_ATTRIBUTE_PTR *result,
                             CK_ULONG *n_result)
{
	CK_ATTRIBUTE_PTR attrs;
	uint32_t n_attrs, i;
	uint32_t value;

	assert (msg != NULL);
	assert (result != NULL);
	assert (n_result != NULL);

	/* Make sure this is in the rigth order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "fA"));

	/* Read the number of attributes */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &n_attrs))
		return PARSE_ERROR;

	/* Allocate memory for the attribute structures */
	attrs = _p11_rpc_message_alloc_extra (msg, n_attrs * sizeof (CK_ATTRIBUTE));
	if (attrs == NULL)
		return CKR_DEVICE_MEMORY;

	/* Now go through and fill in each one */
	for (i = 0; i < n_attrs; ++i) {

		/* The attribute type */
		if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &value))
			return PARSE_ERROR;

		attrs[i].type = value;

		/* The number of bytes to allocate */
		if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &value))
			return PARSE_ERROR;

		if (value == 0) {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = 0;
		} else {
			attrs[i].pValue = _p11_rpc_message_alloc_extra (msg, value);
			if (!attrs[i].pValue)
				return CKR_DEVICE_MEMORY;
			attrs[i].ulValueLen = value;
		}
	}

	*result = attrs;
	*n_result = n_attrs;
	return CKR_OK;
}

static CK_RV
proto_read_attribute_array (RpcMessage *msg,
                            CK_ATTRIBUTE_PTR *result,
                            CK_ULONG *n_result)
{
	CK_ATTRIBUTE_PTR attrs;
	const unsigned char *data;
	unsigned char valid;
	uint32_t n_attrs, i;
	uint32_t value;
	size_t n_data;

	assert (msg != NULL);
	assert (result != NULL);
	assert (n_result != NULL);

	/* Make sure this is in the rigth order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "aA"));

	/* Read the number of attributes */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &n_attrs))
		return PARSE_ERROR;

	/* Allocate memory for the attribute structures */
	attrs = _p11_rpc_message_alloc_extra (msg, n_attrs * sizeof (CK_ATTRIBUTE));
	if (attrs == NULL)
		return CKR_DEVICE_MEMORY;

	/* Now go through and fill in each one */
	for (i = 0; i < n_attrs; ++i) {

		/* The attribute type */
		if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &value))
			return PARSE_ERROR;

		attrs[i].type = value;

		/* Whether this one is valid or not */
		if (!_p11_buffer_get_byte (&msg->buffer, msg->parsed, &msg->parsed, &valid))
			return PARSE_ERROR;

		if (valid) {
			if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &value))
				return PARSE_ERROR;
			if (!_p11_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, &data, &n_data))
				return PARSE_ERROR;

			if (data != NULL && n_data != value) {
				_p11_message ("attribute length and data do not match");
				return PARSE_ERROR;
			}

			attrs[i].pValue = (CK_VOID_PTR)data;
			attrs[i].ulValueLen = value;
		} else {
			attrs[i].pValue = NULL;
			attrs[i].ulValueLen = -1;
		}
	}

	*result = attrs;
	*n_result = n_attrs;
	return CKR_OK;
}

static CK_RV
proto_write_attribute_array (RpcMessage *msg,
                             CK_ATTRIBUTE_PTR array,
                             CK_ULONG len,
                             CK_RV ret)
{
	assert (msg != NULL);

	/*
	 * When returning an attribute array, certain errors aren't
	 * actually real errors, these are passed through to the other
	 * side along with the attribute array.
	 */

	switch (ret) {
	case CKR_ATTRIBUTE_SENSITIVE:
	case CKR_ATTRIBUTE_TYPE_INVALID:
	case CKR_BUFFER_TOO_SMALL:
	case CKR_OK:
		break;

	/* Pass all other errors straight through */
	default:
		return ret;
	};

	if (!_p11_rpc_message_write_attribute_array (msg, array, len) ||
	    !_p11_rpc_message_write_ulong (msg, ret))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_read_null_string (RpcMessage *msg,
                        CK_UTF8CHAR_PTR *val)
{
	const unsigned char *data;
	size_t n_data;

	assert (msg != NULL);
	assert (val != NULL);

	/* Check that we're supposed to have this at this point */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "z"));

	if (!_p11_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, &data, &n_data))
		return PARSE_ERROR;

	/* Allocate a block of memory for it */
	*val = _p11_rpc_message_alloc_extra (msg, n_data);
	if (*val == NULL)
		return CKR_DEVICE_MEMORY;

	memcpy (*val, data, n_data);
	(*val)[n_data] = 0;

	return CKR_OK;
}

static CK_RV
proto_read_mechanism (RpcMessage *msg,
                      CK_MECHANISM_PTR mech)
{
	const unsigned char *data;
	uint32_t value;
	size_t n_data;

	assert (msg != NULL);
	assert (mech != NULL);

	/* Make sure this is in the right order */
	assert (!msg->signature || _p11_rpc_message_verify_part (msg, "M"));

	/* The mechanism type */
	if (!_p11_buffer_get_uint32 (&msg->buffer, msg->parsed, &msg->parsed, &value))
		return PARSE_ERROR;

	/* The mechanism data */
	if (!_p11_buffer_get_byte_array (&msg->buffer, msg->parsed, &msg->parsed, &data, &n_data))
		return PARSE_ERROR;

	mech->mechanism = value;
	mech->pParameter = (CK_VOID_PTR)data;
	mech->ulParameterLen = n_data;
	return CKR_OK;
}

static CK_RV
proto_write_info (RpcMessage *msg,
                  CK_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_write_version (msg, &info->cryptokiVersion) ||
	    !_p11_rpc_message_write_space_string (msg, info->manufacturerID, 32) ||
	    !_p11_rpc_message_write_ulong (msg, info->flags) ||
	    !_p11_rpc_message_write_space_string (msg, info->libraryDescription, 32) ||
	    !_p11_rpc_message_write_version (msg, &info->libraryVersion))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_slot_info (RpcMessage *msg,
                       CK_SLOT_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_write_space_string (msg, info->slotDescription, 64) ||
	    !_p11_rpc_message_write_space_string (msg, info->manufacturerID, 32) ||
	    !_p11_rpc_message_write_ulong (msg, info->flags) ||
	    !_p11_rpc_message_write_version (msg, &info->hardwareVersion) ||
	    !_p11_rpc_message_write_version (msg, &info->firmwareVersion))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_token_info (RpcMessage *msg,
                        CK_TOKEN_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_write_space_string (msg, info->label, 32) ||
	    !_p11_rpc_message_write_space_string (msg, info->manufacturerID, 32) ||
	    !_p11_rpc_message_write_space_string (msg, info->model, 16) ||
	    !_p11_rpc_message_write_space_string (msg, info->serialNumber, 16) ||
	    !_p11_rpc_message_write_ulong (msg, info->flags) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulMaxSessionCount) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulSessionCount) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulMaxRwSessionCount) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulRwSessionCount) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulMaxPinLen) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulMinPinLen) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulTotalPublicMemory) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulFreePublicMemory) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulTotalPrivateMemory) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulFreePrivateMemory) ||
	    !_p11_rpc_message_write_version (msg, &info->hardwareVersion) ||
	    !_p11_rpc_message_write_version (msg, &info->firmwareVersion) ||
	    !_p11_rpc_message_write_space_string (msg, info->utcTime, 16))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_mechanism_info (RpcMessage *msg,
                            CK_MECHANISM_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_write_ulong (msg, info->ulMinKeySize) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulMaxKeySize) ||
	    !_p11_rpc_message_write_ulong (msg, info->flags))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
proto_write_session_info (RpcMessage *msg,
                          CK_SESSION_INFO_PTR info)
{
	assert (msg != NULL);
	assert (info != NULL);

	if (!_p11_rpc_message_write_ulong (msg, info->slotID) ||
	    !_p11_rpc_message_write_ulong (msg, info->state) ||
	    !_p11_rpc_message_write_ulong (msg, info->flags) ||
	    !_p11_rpc_message_write_ulong (msg, info->ulDeviceError))
		return PREP_ERROR;

	return CKR_OK;
}

static CK_RV
call_ready (RpcMessage *msg)
{
	/*
	 * Called right before invoking the actual PKCS#11 function
	 * Reading out of data is complete, get ready to write return values.
	 */

	if (_p11_rpc_message_buffer_error (msg)) {
		_p11_message ("invalid request from module, probably too short"); \
		return PARSE_ERROR;
	}

	assert (_p11_rpc_message_is_verified (msg));

	if (!_p11_rpc_message_prep (msg, msg->call_id, RPC_RESPONSE)) {
		_p11_message ("couldn't initialize rpc response");
		return CKR_DEVICE_MEMORY;
	}

	return CKR_OK;
}

/* -------------------------------------------------------------------
 * CALL MACROS
 */

#define BEGIN_CALL(call_id) \
	_p11_debug (#call_id ": enter"); \
	assert (msg != NULL); \
	assert (module != NULL); \
	{  \
		CK_ ## call_id _func = module-> call_id; \
		CK_RV _ret = CKR_OK; \
		if (!_func) { _ret = CKR_GENERAL_ERROR; goto _cleanup; }

#define PROCESS_CALL(args) \
		_ret = call_ready (msg); \
		if (_ret != CKR_OK) { goto _cleanup; } \
		_ret = _func args

#define END_CALL \
	_cleanup: \
		_p11_debug ("ret: %d", _ret); \
		return _ret; \
	}

#define IN_BYTE(val) \
	if (!_p11_rpc_message_read_byte (msg, &val)) \
		{ _ret = PARSE_ERROR; goto _cleanup; }

#define IN_ULONG(val) \
	if (!_p11_rpc_message_read_ulong (msg, &val)) \
		{ _ret = PARSE_ERROR; goto _cleanup; }

#define IN_STRING(val) \
	_ret = proto_read_null_string (msg, &val); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_BUFFER(buffer, buffer_len) \
	_ret = proto_read_byte_buffer (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_BYTE_ARRAY(buffer, buffer_len) \
	_ret = proto_read_byte_array (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ULONG_BUFFER(buffer, buffer_len) \
	_ret = proto_read_ulong_buffer (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ATTRIBUTE_BUFFER(buffer, buffer_len) \
	_ret = proto_read_attribute_buffer (msg, &buffer, &buffer_len); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_ATTRIBUTE_ARRAY(attrs, n_attrs) \
	_ret = proto_read_attribute_array (msg, &attrs, &n_attrs); \
	if (_ret != CKR_OK) goto _cleanup;

#define IN_MECHANISM(mech) \
	_ret = proto_read_mechanism (msg, &mech); \
	if (_ret != CKR_OK) goto _cleanup;


#define OUT_ULONG(val) \
	if (_ret == CKR_OK && !_p11_rpc_message_write_ulong (msg, val)) \
		_ret = PREP_ERROR;

#define OUT_BYTE_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_byte_array (msg, array, len, _ret);

#define OUT_ULONG_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_ulong_array (msg, array, len, _ret);

#define OUT_ATTRIBUTE_ARRAY(array, len) \
	/* Note how we filter return codes */ \
	_ret = proto_write_attribute_array (msg, array, len, _ret);

#define OUT_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_info (msg, &val);

#define OUT_SLOT_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_slot_info (msg, &val);

#define OUT_TOKEN_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_token_info (msg, &val);

#define OUT_MECHANISM_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_mechanism_info (msg, &val);

#define OUT_SESSION_INFO(val) \
	if (_ret == CKR_OK) \
		_ret = proto_write_session_info (msg, &val);

/* ---------------------------------------------------------------------------
 * DISPATCH SPECIFIC CALLS
 */

static CK_RV
rpc_C_Initialize (CK_FUNCTION_LIST_PTR module,
                  RpcMessage *msg)
{
	CK_C_Initialize func;
	CK_C_INITIALIZE_ARGS init_args;
	CK_BYTE_PTR handshake;
	CK_ULONG n_handshake;
	CK_RV ret = CKR_OK;

	_p11_debug ("C_Initialize: enter");

	assert (msg != NULL);
	assert (module != NULL);

	ret = proto_read_byte_array (msg, &handshake, &n_handshake);
	if (ret == CKR_OK) {

		/* Check to make sure the header matches */
		if (n_handshake != RPC_HANDSHAKE_LEN ||
		    memcmp (handshake, RPC_HANDSHAKE, n_handshake) != 0) {
			_p11_message ("invalid handshake received from connecting module");
			ret = CKR_GENERAL_ERROR;
		}

		assert (_p11_rpc_message_is_verified (msg));
	}

	memset (&init_args, 0, sizeof (init_args));
	init_args.flags = CKF_OS_LOCKING_OK;

	func = module->C_Initialize;
	assert (func != NULL);
	ret = (func) (&init_args);

	/* Empty response */
	if (ret == CKR_OK)
		ret = call_ready (msg);

	_p11_debug ("ret: %d", ret);
	return ret;
}

static CK_RV
rpc_C_Finalize (CK_FUNCTION_LIST_PTR module,
                RpcMessage *msg)
{
	BEGIN_CALL (C_Finalize);
	PROCESS_CALL ((NULL));
	END_CALL;
}

static CK_RV
rpc_C_GetInfo (CK_FUNCTION_LIST_PTR module,
               RpcMessage *msg)
{
	CK_INFO info;

	BEGIN_CALL (C_GetInfo);
	PROCESS_CALL ((&info));
		OUT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotList (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_BBOOL token_present;
	CK_SLOT_ID_PTR slot_list;
	CK_ULONG count;

	BEGIN_CALL (C_GetSlotList);
		IN_BYTE (token_present);
		IN_ULONG_BUFFER (slot_list, count);
	PROCESS_CALL ((token_present, slot_list, &count));
		OUT_ULONG_ARRAY (slot_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetSlotInfo (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SLOT_ID slot_id;
	CK_SLOT_INFO info;

	BEGIN_CALL (C_GetSlotInfo);
		IN_ULONG (slot_id);
	PROCESS_CALL ((slot_id, &info));
		OUT_SLOT_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetTokenInfo (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SLOT_ID slot_id;
	CK_TOKEN_INFO info;

	BEGIN_CALL (C_GetTokenInfo);
		IN_ULONG (slot_id);
	PROCESS_CALL ((slot_id, &info));
		OUT_TOKEN_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismList (CK_FUNCTION_LIST_PTR module,
                        RpcMessage *msg)
{
	CK_SLOT_ID slot_id;
	CK_MECHANISM_TYPE_PTR mechanism_list;
	CK_ULONG count;

	BEGIN_CALL (C_GetMechanismList);
		IN_ULONG (slot_id);
		IN_ULONG_BUFFER (mechanism_list, count);
	PROCESS_CALL ((slot_id, mechanism_list, &count));
		OUT_ULONG_ARRAY (mechanism_list, count);
	END_CALL;
}

static CK_RV
rpc_C_GetMechanismInfo (CK_FUNCTION_LIST_PTR module,
                        RpcMessage *msg)
{
	CK_SLOT_ID slot_id;
	CK_MECHANISM_TYPE type;
	CK_MECHANISM_INFO info;

	BEGIN_CALL (C_GetMechanismInfo);
		IN_ULONG (slot_id);
		IN_ULONG (type);
	PROCESS_CALL ((slot_id, type, &info));
		OUT_MECHANISM_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitToken (CK_FUNCTION_LIST_PTR module,
                 RpcMessage *msg)
{
	CK_SLOT_ID slot_id;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;
	CK_UTF8CHAR_PTR label;

	BEGIN_CALL (C_InitToken);
		IN_ULONG (slot_id);
		IN_BYTE_ARRAY (pin, pin_len);
		IN_STRING (label);
	PROCESS_CALL ((slot_id, pin, pin_len, label));
	END_CALL;
}

static CK_RV
rpc_C_WaitForSlotEvent (CK_FUNCTION_LIST_PTR module,
                        RpcMessage *msg)
{
	CK_FLAGS flags;
	CK_SLOT_ID slot_id;

	BEGIN_CALL (C_WaitForSlotEvent);
		IN_ULONG (flags);
	PROCESS_CALL ((flags, &slot_id, NULL));
		OUT_ULONG (slot_id);
	END_CALL;
}

static CK_RV
rpc_C_OpenSession (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SLOT_ID slot_id;
	CK_FLAGS flags;
	CK_SESSION_HANDLE session;

	BEGIN_CALL (C_OpenSession);
		IN_ULONG (slot_id);
		IN_ULONG (flags);
	PROCESS_CALL ((slot_id, flags, NULL, NULL, &session));
		OUT_ULONG (session);
	END_CALL;
}


static CK_RV
rpc_C_CloseSession (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (C_CloseSession);
		IN_ULONG (session);
	PROCESS_CALL ((session));
	END_CALL;
}

static CK_RV
rpc_C_CloseAllSessions (CK_FUNCTION_LIST_PTR module,
                        RpcMessage *msg)
{
	CK_SLOT_ID slot_id;

	/* Slot id becomes appartment so lower layers can tell clients apart. */

	BEGIN_CALL (C_CloseAllSessions);
		IN_ULONG (slot_id);
	PROCESS_CALL ((slot_id));
	END_CALL;
}

static CK_RV
rpc_C_GetFunctionStatus (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (C_GetFunctionStatus);
		IN_ULONG (session);
	PROCESS_CALL ((session));
	END_CALL;
}

static CK_RV
rpc_C_CancelFunction (CK_FUNCTION_LIST_PTR module,
                      RpcMessage *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (C_CancelFunction);
		IN_ULONG (session);
	PROCESS_CALL ((session));
	END_CALL;
}

static CK_RV
rpc_C_GetSessionInfo (CK_FUNCTION_LIST_PTR module,
                      RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_SESSION_INFO info;

	BEGIN_CALL (C_GetSessionInfo);
		IN_ULONG (session);
	PROCESS_CALL ((session, &info));
		OUT_SESSION_INFO (info);
	END_CALL;
}

static CK_RV
rpc_C_InitPIN (CK_FUNCTION_LIST_PTR module,
               RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;

	BEGIN_CALL (C_InitPIN);
		IN_ULONG (session);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL ((session, pin, pin_len));
	END_CALL;
}

static CK_RV
rpc_C_SetPIN (CK_FUNCTION_LIST_PTR module,
              RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_UTF8CHAR_PTR old_pin;
	CK_ULONG old_len;
	CK_UTF8CHAR_PTR new_pin;
	CK_ULONG new_len;

	BEGIN_CALL (C_SetPIN);
		IN_ULONG (session);
		IN_BYTE_ARRAY (old_pin, old_len);
		IN_BYTE_ARRAY (new_pin, new_len);
	PROCESS_CALL ((session, old_pin, old_len, new_pin, new_len));
	END_CALL;
}

static CK_RV
rpc_C_GetOperationState (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR operation_state;
	CK_ULONG operation_state_len;

	BEGIN_CALL (C_GetOperationState);
		IN_ULONG (session);
		IN_BYTE_BUFFER (operation_state, operation_state_len);
	PROCESS_CALL ((session, operation_state, &operation_state_len));
		OUT_BYTE_ARRAY (operation_state, operation_state_len);
	END_CALL;
}

static CK_RV
rpc_C_SetOperationState (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR operation_state;
	CK_ULONG operation_state_len;
	CK_OBJECT_HANDLE encryption_key;
	CK_OBJECT_HANDLE authentication_key;

	BEGIN_CALL (C_SetOperationState);
		IN_ULONG (session);
		IN_BYTE_ARRAY (operation_state, operation_state_len);
		IN_ULONG (encryption_key);
		IN_ULONG (authentication_key);
	PROCESS_CALL ((session, operation_state, operation_state_len, encryption_key, authentication_key));
	END_CALL;
}

static CK_RV
rpc_C_Login (CK_FUNCTION_LIST_PTR module,
             RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_USER_TYPE user_type;
	CK_UTF8CHAR_PTR pin;
	CK_ULONG pin_len;

	BEGIN_CALL (C_Login);
		IN_ULONG (session);
		IN_ULONG (user_type);
		IN_BYTE_ARRAY (pin, pin_len);
	PROCESS_CALL ((session, user_type, pin, pin_len));
	END_CALL;
}

static CK_RV
rpc_C_Logout (CK_FUNCTION_LIST_PTR module,
              RpcMessage *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (C_Logout);
		IN_ULONG (session);
	PROCESS_CALL ((session));
	END_CALL;
}

/* -----------------------------------------------------------------------------
 * OBJECT OPERATIONS
 */

static CK_RV
rpc_C_CreateObject (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE new_object;

	BEGIN_CALL (C_CreateObject);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((session, template, count, &new_object));
		OUT_ULONG (new_object);
	END_CALL;
}

static CK_RV
rpc_C_CopyObject (CK_FUNCTION_LIST_PTR module,
                  RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE new_object;

	BEGIN_CALL (C_CopyObject);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((session, object, template, count, &new_object));
		OUT_ULONG (new_object);
	END_CALL;
}

static CK_RV
rpc_C_DestroyObject (CK_FUNCTION_LIST_PTR module,
                     RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;

	BEGIN_CALL (C_DestroyObject);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL ((session, object));
	END_CALL;
}

static CK_RV
rpc_C_GetObjectSize (CK_FUNCTION_LIST_PTR module,
                     RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ULONG size;

	BEGIN_CALL (C_GetObjectSize);
		IN_ULONG (session);
		IN_ULONG (object);
	PROCESS_CALL ((session, object, &size));
		OUT_ULONG (size);
	END_CALL;
}

static CK_RV
rpc_C_GetAttributeValue (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL (C_GetAttributeValue);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_BUFFER (template, count);
	PROCESS_CALL ((session, object, template, count));
		OUT_ATTRIBUTE_ARRAY (template, count);
	END_CALL;
}

static CK_RV
rpc_C_SetAttributeValue (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL (C_SetAttributeValue);
		IN_ULONG (session);
		IN_ULONG (object);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((session, object, template, count));
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsInit (CK_FUNCTION_LIST_PTR module,
                       RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;

	BEGIN_CALL (C_FindObjectsInit);
		IN_ULONG (session);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((session, template, count));
	END_CALL;
}

static CK_RV
rpc_C_FindObjects (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE_PTR objects;
	CK_ULONG max_object_count;
	CK_ULONG object_count;

	BEGIN_CALL (C_FindObjects);
		IN_ULONG (session);
		IN_ULONG_BUFFER (objects, max_object_count);
	PROCESS_CALL ((session, objects, max_object_count, &object_count));
		OUT_ULONG_ARRAY (objects, object_count);
	END_CALL;
}

static CK_RV
rpc_C_FindObjectsFinal (CK_FUNCTION_LIST_PTR module,
                        RpcMessage *msg)
{
	CK_SESSION_HANDLE session;

	BEGIN_CALL (C_FindObjectsFinal);
		IN_ULONG (session);
	PROCESS_CALL ((session));
	END_CALL;
}

static CK_RV
rpc_C_EncryptInit (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_EncryptInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((session, &mechanism, key));
	END_CALL;

}

static CK_RV
rpc_C_Encrypt (CK_FUNCTION_LIST_PTR module,
               RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR encrypted_data;
	CK_ULONG encrypted_data_len;

	BEGIN_CALL (C_Encrypt);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (encrypted_data, encrypted_data_len);
	PROCESS_CALL ((session, data, data_len, encrypted_data, &encrypted_data_len));
		OUT_BYTE_ARRAY (encrypted_data, encrypted_data_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptUpdate (CK_FUNCTION_LIST_PTR module,
                     RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL (C_EncryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL ((session, part, part_len, encrypted_part, &encrypted_part_len));
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_EncryptFinal (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR last_encrypted_part;
	CK_ULONG last_encrypted_part_len;

	BEGIN_CALL (C_EncryptFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_encrypted_part, last_encrypted_part_len);
	PROCESS_CALL ((session, last_encrypted_part, &last_encrypted_part_len));
		OUT_BYTE_ARRAY (last_encrypted_part, last_encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptInit (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_DecryptInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((session, &mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_Decrypt (CK_FUNCTION_LIST_PTR module,
               RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_data;
	CK_ULONG encrypted_data_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;

	BEGIN_CALL (C_Decrypt);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_data, encrypted_data_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL ((session, encrypted_data, encrypted_data_len, data, &data_len));
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptUpdate (CK_FUNCTION_LIST_PTR module,
                     RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (C_DecryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_part, encrypted_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL ((session, encrypted_part, encrypted_part_len, part, &part_len));
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptFinal (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR last_part;
	CK_ULONG last_part_len;

	BEGIN_CALL (C_DecryptFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (last_part, last_part_len);
	PROCESS_CALL ((session, last_part, &last_part_len));
		OUT_BYTE_ARRAY (last_part, last_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestInit (CK_FUNCTION_LIST_PTR module,
                  RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;

	BEGIN_CALL (C_DigestInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
	PROCESS_CALL ((session, &mechanism));
	END_CALL;
}

static CK_RV
rpc_C_Digest (CK_FUNCTION_LIST_PTR module,
              RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;

	BEGIN_CALL (C_Digest);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL ((session, data, data_len, digest, &digest_len));
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestUpdate (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (C_DigestUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL ((session, part, part_len));
	END_CALL;
}

static CK_RV
rpc_C_DigestKey (CK_FUNCTION_LIST_PTR module,
                 RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_DigestKey);
		IN_ULONG (session);
		IN_ULONG (key);
	PROCESS_CALL ((session, key));
	END_CALL;
}

static CK_RV
rpc_C_DigestFinal (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR digest;
	CK_ULONG digest_len;

	BEGIN_CALL (C_DigestFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (digest, digest_len);
	PROCESS_CALL ((session, digest, &digest_len));
		OUT_BYTE_ARRAY (digest, digest_len);
	END_CALL;
}

static CK_RV
rpc_C_SignInit (CK_FUNCTION_LIST_PTR module,
                RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_SignInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((session, &mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_Sign (CK_FUNCTION_LIST_PTR module,
            RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (C_Sign);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((session, part, part_len, signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;

}

static CK_RV
rpc_C_SignUpdate (CK_FUNCTION_LIST_PTR module,
                  RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (C_SignUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL ((session, part, part_len));
	END_CALL;
}

static CK_RV
rpc_C_SignFinal (CK_FUNCTION_LIST_PTR module,
                 RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (C_SignFinal);
		IN_ULONG (session);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((session, signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_SignRecoverInit (CK_FUNCTION_LIST_PTR module,
                       RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_SignRecoverInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((session, &mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_SignRecover (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (C_SignRecover);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_BUFFER (signature, signature_len);
	PROCESS_CALL ((session, data, data_len, signature, &signature_len));
		OUT_BYTE_ARRAY (signature, signature_len);
	END_CALL;
}

static CK_RV
rpc_C_VerifyInit (CK_FUNCTION_LIST_PTR module,
                  RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_VerifyInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((session, &mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_Verify (CK_FUNCTION_LIST_PTR module,
              RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR data;
	CK_ULONG data_len;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (C_Verify);
		IN_ULONG (session);
		IN_BYTE_ARRAY (data, data_len);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL ((session, data, data_len, signature, signature_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyUpdate (CK_FUNCTION_LIST_PTR module,
                    RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (C_VerifyUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
	PROCESS_CALL ((session, part, part_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyFinal (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;

	BEGIN_CALL (C_VerifyFinal);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
	PROCESS_CALL ((session, signature, signature_len));
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecoverInit (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_VerifyRecoverInit);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (key);
	PROCESS_CALL ((session, &mechanism, key));
	END_CALL;
}

static CK_RV
rpc_C_VerifyRecover (CK_FUNCTION_LIST_PTR module,
                     RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR signature;
	CK_ULONG signature_len;
	CK_BYTE_PTR data;
	CK_ULONG data_len;

	BEGIN_CALL (C_VerifyRecover);
		IN_ULONG (session);
		IN_BYTE_ARRAY (signature, signature_len);
		IN_BYTE_BUFFER (data, data_len);
	PROCESS_CALL ((session, signature, signature_len, data, &data_len));
		OUT_BYTE_ARRAY (data, data_len);
	END_CALL;
}

static CK_RV
rpc_C_DigestEncryptUpdate (CK_FUNCTION_LIST_PTR module,
                           RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL (C_DigestEncryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL ((session, part, part_len, encrypted_part, &encrypted_part_len));
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptDigestUpdate (CK_FUNCTION_LIST_PTR module,
                           RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (C_DecryptDigestUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_part, encrypted_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL ((session, encrypted_part, encrypted_part_len, part, &part_len));
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_SignEncryptUpdate (CK_FUNCTION_LIST_PTR module,
                         RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR part;
	CK_ULONG part_len;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;

	BEGIN_CALL (C_SignEncryptUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (part, part_len);
		IN_BYTE_BUFFER (encrypted_part, encrypted_part_len);
	PROCESS_CALL ((session, part, part_len, encrypted_part, &encrypted_part_len));
		OUT_BYTE_ARRAY (encrypted_part, encrypted_part_len);
	END_CALL;
}

static CK_RV
rpc_C_DecryptVerifyUpdate (CK_FUNCTION_LIST_PTR module,
                           RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR encrypted_part;
	CK_ULONG encrypted_part_len;
	CK_BYTE_PTR part;
	CK_ULONG part_len;

	BEGIN_CALL (C_DecryptVerifyUpdate);
		IN_ULONG (session);
		IN_BYTE_ARRAY (encrypted_part, encrypted_part_len);
		IN_BYTE_BUFFER (part, part_len);
	PROCESS_CALL ((session, encrypted_part, encrypted_part_len, part, &part_len));
		OUT_BYTE_ARRAY (part, part_len);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKey (CK_FUNCTION_LIST_PTR module,
                   RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_GenerateKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (template, count);
	PROCESS_CALL ((session, &mechanism, template, count, &key));
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_GenerateKeyPair (CK_FUNCTION_LIST_PTR module,
                       RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_ATTRIBUTE_PTR public_key_template;
	CK_ULONG public_key_attribute_count;
	CK_ATTRIBUTE_PTR private_key_template;
	CK_ULONG private_key_attribute_count;
	CK_OBJECT_HANDLE public_key;
	CK_OBJECT_HANDLE private_key;

	BEGIN_CALL (C_GenerateKeyPair);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ATTRIBUTE_ARRAY (public_key_template, public_key_attribute_count);
		IN_ATTRIBUTE_ARRAY (private_key_template, private_key_attribute_count);
	PROCESS_CALL ((session, &mechanism, public_key_template, public_key_attribute_count, private_key_template, private_key_attribute_count, &public_key, &private_key));
		OUT_ULONG (public_key);
		OUT_ULONG (private_key);
	END_CALL;
}

static CK_RV
rpc_C_WrapKey (CK_FUNCTION_LIST_PTR module,
               RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE wrapping_key;
	CK_OBJECT_HANDLE key;
	CK_BYTE_PTR wrapped_key;
	CK_ULONG wrapped_key_len;

	BEGIN_CALL (C_WrapKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (wrapping_key);
		IN_ULONG (key);
		IN_BYTE_BUFFER (wrapped_key, wrapped_key_len);
	PROCESS_CALL ((session, &mechanism, wrapping_key, key, wrapped_key, &wrapped_key_len));
		OUT_BYTE_ARRAY (wrapped_key, wrapped_key_len);
	END_CALL;
}

static CK_RV
rpc_C_UnwrapKey (CK_FUNCTION_LIST_PTR module,
                 RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE unwrapping_key;
	CK_BYTE_PTR wrapped_key;
	CK_ULONG wrapped_key_len;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG attribute_count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_UnwrapKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (unwrapping_key);
		IN_BYTE_ARRAY (wrapped_key, wrapped_key_len);
		IN_ATTRIBUTE_ARRAY (template, attribute_count);
	PROCESS_CALL ((session, &mechanism, unwrapping_key, wrapped_key, wrapped_key_len, template, attribute_count, &key));
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_DeriveKey (CK_FUNCTION_LIST_PTR module,
                 RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_MECHANISM mechanism;
	CK_OBJECT_HANDLE base_key;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG attribute_count;
	CK_OBJECT_HANDLE key;

	BEGIN_CALL (C_DeriveKey);
		IN_ULONG (session);
		IN_MECHANISM (mechanism);
		IN_ULONG (base_key);
		IN_ATTRIBUTE_ARRAY (template, attribute_count);
	PROCESS_CALL ((session, &mechanism, base_key, template, attribute_count, &key));
		OUT_ULONG (key);
	END_CALL;
}

static CK_RV
rpc_C_SeedRandom (CK_FUNCTION_LIST_PTR module,
                  RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR seed;
	CK_ULONG seed_len;

	BEGIN_CALL (C_SeedRandom);
		IN_ULONG (session);
		IN_BYTE_ARRAY (seed, seed_len);
	PROCESS_CALL ((session, seed, seed_len));
	END_CALL;
}

static CK_RV
rpc_C_GenerateRandom (CK_FUNCTION_LIST_PTR module,
                      RpcMessage *msg)
{
	CK_SESSION_HANDLE session;
	CK_BYTE_PTR random_data;
	CK_ULONG random_len;

	BEGIN_CALL (C_GenerateRandom);
		IN_ULONG (session);
		IN_BYTE_BUFFER (random_data, random_len);
	PROCESS_CALL ((session, random_data, random_len));
		OUT_BYTE_ARRAY (random_data, random_len);
	END_CALL;
}

int
_p11_rpc_server_perform (CK_FUNCTION_LIST_PTR module,
                         unsigned char **data,
                         size_t *n_data)
{
	RpcMessage msg;
	CK_RV ret;
	int req_id;

	assert (module != NULL);
	assert (data != NULL);
	assert (n_data != NULL);

	_p11_rpc_message_init (&msg, log_allocator);
	_p11_buffer_init_allocated (&msg.buffer, *data, *n_data, log_allocator);

	if (!_p11_rpc_message_parse (&msg, RPC_REQUEST)) {
		_p11_rpc_message_clear (&msg);
		return 0;
	}

	/* This should have been checked by the parsing code */
	assert (msg.call_id > RPC_CALL_ERROR);
	assert (msg.call_id < RPC_CALL_MAX);
	req_id = msg.call_id;

	switch(req_id) {
	#define CASE_CALL(name) \
	case RPC_CALL_##name: \
		ret = rpc_##name (module, &msg); \
		break;
	CASE_CALL (C_Initialize)
	CASE_CALL (C_Finalize)
	CASE_CALL (C_GetInfo)
	CASE_CALL (C_GetSlotList)
	CASE_CALL (C_GetSlotInfo)
	CASE_CALL (C_GetTokenInfo)
	CASE_CALL (C_GetMechanismList)
	CASE_CALL (C_GetMechanismInfo)
	CASE_CALL (C_InitToken)
	CASE_CALL (C_WaitForSlotEvent)
	CASE_CALL (C_OpenSession)
	CASE_CALL (C_CloseSession)
	CASE_CALL (C_CloseAllSessions)
	CASE_CALL (C_GetFunctionStatus)
	CASE_CALL (C_CancelFunction)
	CASE_CALL (C_GetSessionInfo)
	CASE_CALL (C_InitPIN)
	CASE_CALL (C_SetPIN)
	CASE_CALL (C_GetOperationState)
	CASE_CALL (C_SetOperationState)
	CASE_CALL (C_Login)
	CASE_CALL (C_Logout)
	CASE_CALL (C_CreateObject)
	CASE_CALL (C_CopyObject)
	CASE_CALL (C_DestroyObject)
	CASE_CALL (C_GetObjectSize)
	CASE_CALL (C_GetAttributeValue)
	CASE_CALL (C_SetAttributeValue)
	CASE_CALL (C_FindObjectsInit)
	CASE_CALL (C_FindObjects)
	CASE_CALL (C_FindObjectsFinal)
	CASE_CALL (C_EncryptInit)
	CASE_CALL (C_Encrypt)
	CASE_CALL (C_EncryptUpdate)
	CASE_CALL (C_EncryptFinal)
	CASE_CALL (C_DecryptInit)
	CASE_CALL (C_Decrypt)
	CASE_CALL (C_DecryptUpdate)
	CASE_CALL (C_DecryptFinal)
	CASE_CALL (C_DigestInit)
	CASE_CALL (C_Digest)
	CASE_CALL (C_DigestUpdate)
	CASE_CALL (C_DigestKey)
	CASE_CALL (C_DigestFinal)
	CASE_CALL (C_SignInit)
	CASE_CALL (C_Sign)
	CASE_CALL (C_SignUpdate)
	CASE_CALL (C_SignFinal)
	CASE_CALL (C_SignRecoverInit)
	CASE_CALL (C_SignRecover)
	CASE_CALL (C_VerifyInit)
	CASE_CALL (C_Verify)
	CASE_CALL (C_VerifyUpdate)
	CASE_CALL (C_VerifyFinal)
	CASE_CALL (C_VerifyRecoverInit)
	CASE_CALL (C_VerifyRecover)
	CASE_CALL (C_DigestEncryptUpdate)
	CASE_CALL (C_DecryptDigestUpdate)
	CASE_CALL (C_SignEncryptUpdate)
	CASE_CALL (C_DecryptVerifyUpdate)
	CASE_CALL (C_GenerateKey)
	CASE_CALL (C_GenerateKeyPair)
	CASE_CALL (C_WrapKey)
	CASE_CALL (C_UnwrapKey)
	CASE_CALL (C_DeriveKey)
	CASE_CALL (C_SeedRandom)
	CASE_CALL (C_GenerateRandom)
	#undef CASE_CALL
	default:
		/* This should have been caught by the parse code */
		assert (0 && "Unchecked call");
		break;
	};

	if (ret == CKR_OK) {
		if (_p11_rpc_message_buffer_error (&msg)) {
			_p11_message ("out of memory error putting together message");
			ret = PREP_ERROR;
		}
	}

	/* A filled in response */
	if (ret == CKR_OK) {

		/*
		 * Since we're dealing with many many functions above generating
		 * these messages we want to make sure each of them actually
		 * does what it's supposed to.
		 */

		assert (_p11_rpc_message_is_verified (&msg));
		assert (msg.call_type == RPC_RESPONSE);
		assert (msg.call_id == req_id);
		assert (rpc_calls[msg.call_id].response);
		assert (strcmp (rpc_calls[msg.call_id].response, msg.signature) == 0);

	/* Fill in an error respnose */
	} else {
		if (!_p11_rpc_message_prep (&msg, RPC_CALL_ERROR, RPC_RESPONSE) ||
		    !_p11_rpc_message_write_ulong (&msg, (uint32_t)ret) ||
		    _p11_rpc_message_buffer_error (&msg)) {
			_p11_message ("out of memory responding with error");
			_p11_rpc_message_clear (&msg);
			return 0;
		}
	}

	*data = _p11_buffer_uninit_steal (&msg.buffer, n_data);
	_p11_rpc_message_clear (&msg);
	return 1;
}
