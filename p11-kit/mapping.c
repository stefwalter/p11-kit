/*
 * Copyright (C) 2008 Stefan Walter
 * Copyright (C) 2011 Collabora Ltd.
 * Copyright (C) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stefw@collabora.co.uk>
 */

#include "config.h"

#if 0
#define DEBUG_FLAG DEBUG_PROXY
#include "debug.h"
#include "hashmap.h"
#define CRYPTOKI_EXPORTS
#include "pkcs11.h"
#include "p11-kit.h"
#include "private.h"
#include "util.h"

#include <sys/types.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#endif

/* Start wrap slots slightly higher for testing */
#define MAPPING_OFFSET 0x10
#define FIRST_HANDLE   0x10

typedef struct _Mapping {
	CK_SLOT_ID wrap_slot;
	CK_SLOT_ID real_slot;
	CK_FUNCTION_LIST_PTR funcs;
} Mapping;

typedef struct _Session {
	CK_SESSION_HANDLE wrap_session;
	CK_SESSION_HANDLE real_session;
	CK_SLOT_ID wrap_slot;
} Session;

/*
 * Shared data between threads, protected by the mutex, a structure so
 * we can audit thread safety easier.
 */
static struct _Mappings {
	Mapping *mappings;
	unsigned int n_mappings;
	int mappings_refs;
	hashmap *sessions;
	CK_ULONG last_handle;
} gl = { NULL, 0, 0, NULL, FIRST_HANDLE };

static CK_RV
map_slot_unlocked (CK_SLOT_ID slot,
                   Mapping *mapping)
{
	assert (mapping);

	if (slot < MAPPING_OFFSET)
		return CKR_SLOT_ID_INVALID;
	slot -= MAPPING_OFFSET;

	if (slot > gl.n_mappings) {
		return CKR_SLOT_ID_INVALID;
	} else {
		assert (gl.mappings);
		memcpy (mapping, &gl.mappings[slot], sizeof (Mapping));
		return CKR_OK;
	}
}

static CK_RV
map_slot_to_real (CK_SLOT_ID_PTR slot,
                  Mapping *mapping)
{
	CK_RV rv;

	assert (mapping);

	_p11_lock ();

		if (!gl.mappings)
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		else
			rv = map_slot_unlocked (*slot, mapping);
		if (rv == CKR_OK)
			*slot = mapping->real_slot;

	_p11_unlock ();

	return rv;
}

static CK_RV
map_session_to_real (CK_SESSION_HANDLE_PTR handle,
                     Mapping *mapping,
                     Session *session)
{
	CK_RV rv = CKR_OK;
	Session *sess;

	assert (handle);
	assert (mapping);

	_p11_lock ();

		if (!gl.sessions) {
			rv = CKR_CRYPTOKI_NOT_INITIALIZED;
		} else {
			assert (gl.sessions);
			sess = _p11_hash_get (gl.sessions, handle);
			if (sess != NULL) {
				*handle = sess->real_session;
				rv = map_slot_unlocked (sess->wrap_slot, mapping);
				if (session != NULL)
					memcpy (session, sess, sizeof (Session));
			} else {
				rv = CKR_SESSION_HANDLE_INVALID;
			}
		}

	_p11_unlock ();

	return rv;
}

static void
finalize_mappings_unlocked (void)
{
	assert (gl.mappings_refs);

	if (--gl.mappings_refs)
		return;

	/* No more mappings */
	free (gl.mappings);
	gl.mappings = NULL;
	gl.n_mappings = 0;

	/* no more sessions */
	_p11_hash_free (gl.sessions);
	gl.sessions = NULL;
}

static CK_RV
initialize_mappings_unlocked_reentrant (void)
{
	Mapping *mappings = NULL;
	int n_mappings = 0;
	CK_SLOT_ID_PTR slots;
	CK_ULONG i, count;
	CK_RV rv = CKR_OK;

	assert (!gl.mappings);

#if 0
	/* Another thread raced us here due to above reentrancy */
	if (gl.mappings) {
		free (mappings);
		return CKR_OK;
	}

	assert (!gl.sessions);
	gl.mappings = mappings;
	gl.n_mappings = n_mappings;
	gl.sessions = _p11_hash_create (_p11_hash_ulongptr_hash, _p11_hash_ulongptr_equal, NULL, free);
	++gl.mappings_refs;
#endif

	/* Any cleanup necessary for failure will happen at caller */
	return rv;
}
