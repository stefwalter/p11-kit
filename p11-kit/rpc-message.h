/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* rpc-private.h - various ids and signatures for our protocol

   Copyright (C) 2008, Stef Walter

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

   Author: Stef Walter <stef@memberwebs.com>
*/

#ifndef _RPC_MESSAGE_H
#define _RPC_MESSAGE_H

#include <stdlib.h>
#include <stdarg.h>

#include "buffer.h"
#include "pkcs11.h"

/* The calls, must be in sync with array below */
enum {
	RPC_CALL_ERROR = 0,

	RPC_CALL_C_Initialize,
	RPC_CALL_C_Finalize,
	RPC_CALL_C_GetInfo,
	RPC_CALL_C_GetSlotList,
	RPC_CALL_C_GetSlotInfo,
	RPC_CALL_C_GetTokenInfo,
	RPC_CALL_C_GetMechanismList,
	RPC_CALL_C_GetMechanismInfo,
	RPC_CALL_C_InitToken,
	RPC_CALL_C_WaitForSlotEvent,

	RPC_CALL_C_OpenSession,

	RPC_CALL_C_CloseSession,
	RPC_CALL_C_CloseAllSessions,
	RPC_CALL_C_GetFunctionStatus,
	RPC_CALL_C_CancelFunction,

	RPC_CALL_C_GetSessionInfo,
	RPC_CALL_C_InitPIN,
	RPC_CALL_C_SetPIN,
	RPC_CALL_C_GetOperationState,
	RPC_CALL_C_SetOperationState,
	RPC_CALL_C_Login,
	RPC_CALL_C_Logout,
	RPC_CALL_C_CreateObject,
	RPC_CALL_C_CopyObject,
	RPC_CALL_C_DestroyObject,
	RPC_CALL_C_GetObjectSize,
	RPC_CALL_C_GetAttributeValue,
	RPC_CALL_C_SetAttributeValue,
	RPC_CALL_C_FindObjectsInit,
	RPC_CALL_C_FindObjects,
	RPC_CALL_C_FindObjectsFinal,
	RPC_CALL_C_EncryptInit,
	RPC_CALL_C_Encrypt,
	RPC_CALL_C_EncryptUpdate,
	RPC_CALL_C_EncryptFinal,
	RPC_CALL_C_DecryptInit,
	RPC_CALL_C_Decrypt,
	RPC_CALL_C_DecryptUpdate,
	RPC_CALL_C_DecryptFinal,
	RPC_CALL_C_DigestInit,
	RPC_CALL_C_Digest,
	RPC_CALL_C_DigestUpdate,
	RPC_CALL_C_DigestKey,
	RPC_CALL_C_DigestFinal,
	RPC_CALL_C_SignInit,
	RPC_CALL_C_Sign,
	RPC_CALL_C_SignUpdate,
	RPC_CALL_C_SignFinal,
	RPC_CALL_C_SignRecoverInit,
	RPC_CALL_C_SignRecover,
	RPC_CALL_C_VerifyInit,
	RPC_CALL_C_Verify,
	RPC_CALL_C_VerifyUpdate,
	RPC_CALL_C_VerifyFinal,
	RPC_CALL_C_VerifyRecoverInit,
	RPC_CALL_C_VerifyRecover,
	RPC_CALL_C_DigestEncryptUpdate,
	RPC_CALL_C_DecryptDigestUpdate,
	RPC_CALL_C_SignEncryptUpdate,
	RPC_CALL_C_DecryptVerifyUpdate,
	RPC_CALL_C_GenerateKey,
	RPC_CALL_C_GenerateKeyPair,
	RPC_CALL_C_WrapKey,
	RPC_CALL_C_UnwrapKey,
	RPC_CALL_C_DeriveKey,
	RPC_CALL_C_SeedRandom,
	RPC_CALL_C_GenerateRandom,

	RPC_CALL_MAX
};

typedef struct _RpcCall {
	int call_id;
	const char* name;
	const char* request;
	const char* response;
} RpcCall;

/*
 *  a_ = prefix denotes array of _
 *  A  = CK_ATTRIBUTE
 *  f_ = prefix denotes buffer for _
 *  M  = CK_MECHANISM
 *  u  = CK_ULONG
 *  s  = space padded string
 *  v  = CK_VERSION
 *  y  = CK_BYTE
 *  z  = null terminated string
 */

static const RpcCall rpc_calls[] = {
	{ RPC_CALL_ERROR,                  "ERROR",                  NULL,      NULL                   },
	{ RPC_CALL_C_Initialize,           "C_Initialize",           "ay",      ""                     },
	{ RPC_CALL_C_Finalize,             "C_Finalize",             "",        ""                     },
	{ RPC_CALL_C_GetInfo,              "C_GetInfo",              "",        "vsusv"                },
	{ RPC_CALL_C_GetSlotList,          "C_GetSlotList",          "yfu",     "au"                   },
	{ RPC_CALL_C_GetSlotInfo,          "C_GetSlotInfo",          "u",       "ssuvv"                },
	{ RPC_CALL_C_GetTokenInfo,         "C_GetTokenInfo",         "u",       "ssssuuuuuuuuuuuvvs"   },
	{ RPC_CALL_C_GetMechanismList,     "C_GetMechanismList",     "ufu",     "au"                   },
	{ RPC_CALL_C_GetMechanismInfo,     "C_GetMechanismInfo",     "uu",      "uuu"                  },
	{ RPC_CALL_C_InitToken,            "C_InitToken",            "uayz",    ""                     },
	{ RPC_CALL_C_WaitForSlotEvent,     "C_WaitForSlotEvent",     "u",       "u"                    },
	{ RPC_CALL_C_OpenSession,          "C_OpenSession",          "uu",      "u"                    },
	{ RPC_CALL_C_CloseSession,         "C_CloseSession",         "u",       ""                     },
	{ RPC_CALL_C_CloseAllSessions,     "C_CloseAllSessions",     "u",       ""                     },
	{ RPC_CALL_C_GetFunctionStatus,    "C_GetFunctionStatus",    "u",       ""                     },
	{ RPC_CALL_C_CancelFunction,       "C_CancelFunction",       "u",       ""                     },
	{ RPC_CALL_C_GetSessionInfo,       "C_GetSessionInfo",       "u",       "uuuu"                 },
	{ RPC_CALL_C_InitPIN,              "C_InitPIN",              "uay",     ""                     },
	{ RPC_CALL_C_SetPIN,               "C_SetPIN",               "uayay",   ""                     },
	{ RPC_CALL_C_GetOperationState,    "C_GetOperationState",    "ufy",     "ay"                   },
	{ RPC_CALL_C_SetOperationState,    "C_SetOperationState",    "uayuu",   ""                     },
	{ RPC_CALL_C_Login,                "C_Login",                "uuay",    ""                     },
	{ RPC_CALL_C_Logout,               "C_Logout",               "u",       ""                     },
	{ RPC_CALL_C_CreateObject,         "C_CreateObject",         "uaA",     "u"                    },
	{ RPC_CALL_C_CopyObject,           "C_CopyObject",           "uuaA",    "u"                    },
	{ RPC_CALL_C_DestroyObject,        "C_DestroyObject",        "uu",      ""                     },
	{ RPC_CALL_C_GetObjectSize,        "C_GetObjectSize",        "uu",      "u"                    },
	{ RPC_CALL_C_GetAttributeValue,    "C_GetAttributeValue",    "uufA",    "aAu"                  },
	{ RPC_CALL_C_SetAttributeValue,    "C_SetAttributeValue",    "uuaA",    ""                     },
	{ RPC_CALL_C_FindObjectsInit,      "C_FindObjectsInit",      "uaA",     ""                     },
	{ RPC_CALL_C_FindObjects,          "C_FindObjects",          "ufu",     "au"                   },
	{ RPC_CALL_C_FindObjectsFinal,     "C_FindObjectsFinal",     "u",       ""                     },
	{ RPC_CALL_C_EncryptInit,          "C_EncryptInit",          "uMu",     ""                     },
	{ RPC_CALL_C_Encrypt,              "C_Encrypt",              "uayfy",   "ay"                   },
	{ RPC_CALL_C_EncryptUpdate,        "C_EncryptUpdate",        "uayfy",   "ay"                   },
	{ RPC_CALL_C_EncryptFinal,         "C_EncryptFinal",         "ufy",     "ay"                   },
	{ RPC_CALL_C_DecryptInit,          "C_DecryptInit",          "uMu",     ""                     },
	{ RPC_CALL_C_Decrypt,              "C_Decrypt",              "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptUpdate,        "C_DecryptUpdate",        "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptFinal,         "C_DecryptFinal",         "ufy",     "ay"                   },
	{ RPC_CALL_C_DigestInit,           "C_DigestInit",           "uM",      ""                     },
	{ RPC_CALL_C_Digest,               "C_Digest",               "uayfy",   "ay"                   },
	{ RPC_CALL_C_DigestUpdate,         "C_DigestUpdate",         "uay",     ""                     },
	{ RPC_CALL_C_DigestKey,            "C_DigestKey",            "uu",      ""                     },
	{ RPC_CALL_C_DigestFinal,          "C_DigestFinal",          "ufy",     "ay"                   },
	{ RPC_CALL_C_SignInit,             "C_SignInit",             "uMu",     ""                     },
	{ RPC_CALL_C_Sign,                 "C_Sign",                 "uayfy",   "ay"                   },
	{ RPC_CALL_C_SignUpdate,           "C_SignUpdate",           "uay",     ""                     },
	{ RPC_CALL_C_SignFinal,            "C_SignFinal",            "ufy",     "ay"                   },
	{ RPC_CALL_C_SignRecoverInit,      "C_SignRecoverInit",      "uMu",     ""                     },
	{ RPC_CALL_C_SignRecover,          "C_SignRecover",          "uayfy",   "ay"                   },
	{ RPC_CALL_C_VerifyInit,           "C_VerifyInit",           "uMu",     ""                     },
	{ RPC_CALL_C_Verify,               "C_Verify",               "uayay",   ""                     },
	{ RPC_CALL_C_VerifyUpdate,         "C_VerifyUpdate",         "uay",     ""                     },
	{ RPC_CALL_C_VerifyFinal,          "C_VerifyFinal",          "uay",     ""                     },
	{ RPC_CALL_C_VerifyRecoverInit,    "C_VerifyRecoverInit",    "uMu",     ""                     },
	{ RPC_CALL_C_VerifyRecover,        "C_VerifyRecover",        "uayfy",   "ay"                   },
	{ RPC_CALL_C_DigestEncryptUpdate,  "C_DigestEncryptUpdate",  "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptDigestUpdate,  "C_DecryptDigestUpdate",  "uayfy",   "ay"                   },
	{ RPC_CALL_C_SignEncryptUpdate,    "C_SignEncryptUpdate",    "uayfy",   "ay"                   },
	{ RPC_CALL_C_DecryptVerifyUpdate,  "C_DecryptVerifyUpdate",  "uayfy",   "ay"                   },
	{ RPC_CALL_C_GenerateKey,          "C_GenerateKey",          "uMaA",    "u"                    },
	{ RPC_CALL_C_GenerateKeyPair,      "C_GenerateKeyPair",      "uMaAaA",  "uu"                   },
	{ RPC_CALL_C_WrapKey,              "C_WrapKey",              "uMuufy",  "ay"                   },
	{ RPC_CALL_C_UnwrapKey,            "C_UnwrapKey",            "uMuayaA", "u"                    },
	{ RPC_CALL_C_DeriveKey,            "C_DeriveKey",            "uMuaA",   "u"                    },
	{ RPC_CALL_C_SeedRandom,           "C_SeedRandom",           "uay",     ""                     },
	{ RPC_CALL_C_GenerateRandom,       "C_GenerateRandom",       "ufy",     "ay"                   },
};

#ifdef _DEBUG
#define RPC_CHECK_CALLS() \
	{ int i; for (i = 0; i < RPC_CALL_MAX; ++i) assert (rpc_calls[i].call_id == i); }
#endif

#define RPC_HANDSHAKE \
	((unsigned char *)"PRIVATE-GNOME-KEYRING-PKCS11-PROTOCOL-V-1")
#define RPC_HANDSHAKE_LEN \
	(strlen ((char *)RPC_HANDSHAKE))

typedef enum _RpcMessageType {
	RPC_REQUEST = 1,
	RPC_RESPONSE
} RpcMessageType;

typedef struct _RpcMessage {
	int call_id;
	RpcMessageType call_type;
	const char *signature;
	Buffer buffer;

	size_t parsed;
	const char *sigverify;
} RpcMessage;

void                     _p11_rpc_message_init                    (RpcMessage *msg,
                                                                   BufferAllocator allocator);

void                     _p11_rpc_message_clear                   (RpcMessage *msg);

void                     _p11_rpc_message_reset                   (RpcMessage *msg);

#define                  _p11_rpc_message_is_verified(msg)        (!(msg)->sigverify || (msg)->sigverify[0] == 0)

#define                  _p11_rpc_message_buffer_error(msg)       (_p11_buffer_has_error (&(msg)->buffer))

int                      _p11_rpc_message_prep                    (RpcMessage *msg,
                                                                   int call_id,
                                                                   RpcMessageType type);

int                      _p11_rpc_message_parse                   (RpcMessage *msg,
                                                                   RpcMessageType type);

int                      _p11_rpc_message_verify_part             (RpcMessage *msg,
                                                                   const char* part);

int                      _p11_rpc_message_write_byte              (RpcMessage *msg,
                                                                   CK_BYTE val);

int                      _p11_rpc_message_write_ulong             (RpcMessage *msg,
                                                                   CK_ULONG val);

int                      _p11_rpc_message_write_zero_string       (RpcMessage *msg,
                                                                   CK_UTF8CHAR *string);

int                      _p11_rpc_message_write_space_string      (RpcMessage *msg,
                                                                   CK_UTF8CHAR *buffer,
                                                                   CK_ULONG length);

int                      _p11_rpc_message_write_byte_buffer       (RpcMessage *msg,
                                                                   CK_ULONG count);

int                      _p11_rpc_message_write_byte_array        (RpcMessage *msg,
                                                                   CK_BYTE_PTR arr,
                                                                   CK_ULONG num);

int                      _p11_rpc_message_write_ulong_buffer      (RpcMessage *msg,
                                                                   CK_ULONG count);

int                      _p11_rpc_message_write_ulong_array       (RpcMessage *msg,
                                                                   CK_ULONG_PTR arr,
                                                                   CK_ULONG num);

int                      _p11_rpc_message_write_attribute_buffer  (RpcMessage *msg,
                                                                   CK_ATTRIBUTE_PTR arr,
                                                                   CK_ULONG num);

int                      _p11_rpc_message_write_attribute_array   (RpcMessage *msg,
                                                                   CK_ATTRIBUTE_PTR arr,
                                                                   CK_ULONG num);

int                      _p11_rpc_message_write_version           (RpcMessage *msg,
                                                                   CK_VERSION* version);

int                      _p11_rpc_message_read_byte               (RpcMessage *msg,
                                                                   CK_BYTE* val);

int                      _p11_rpc_message_read_ulong              (RpcMessage *msg,
                                                                   CK_ULONG* val);

int                      _p11_rpc_message_read_space_string       (RpcMessage *msg,
                                                                   CK_UTF8CHAR* buffer,
                                                                   CK_ULONG length);

int                      _p11_rpc_message_read_version            (RpcMessage *msg,
                                                                   CK_VERSION* version);

#if 0
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

int    _p11_rpc_mechanism_is_supported        (CK_MECHANISM_TYPE mech);
void   _p11_rpc_mechanism_list_purge          (CK_MECHANISM_TYPE_PTR mechs,
                                               CK_ULONG_PTR n_mechs);
int    _p11_rpc_mechanism_has_sane_parameters (CK_MECHANISM_TYPE type);
int    _p11_rpc_mechanism_has_no_parameters   (CK_MECHANISM_TYPE mech);
#endif

#endif /* _RPC_MESSAGE_H */
