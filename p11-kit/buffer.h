/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* buffer.h - Generic data buffer, used by openssh, gnome-keyring

   Copyright (C) 2007, Stefan Walter

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

#ifndef P11_BUFFER_H
#define P11_BUFFER_H

#include <stdlib.h>
#include <stdint.h>

/* -------------------------------------------------------------------
 * buffer_t
 *
 * IMPORTANT: This is pure vanila standard C, no glib. We need this
 * because certain consumers of this protocol need to be built
 * without linking in any special libraries. ie: the PKCS#11 module.
 *
 * Memory Allocation
 *
 * Callers can set their own allocator. If NULL is used then standard
 * C library heap memory is used and failures will not be fatal. Memory
 * failures will instead result in a zero return value or
 * _p11_buffer_has_error() returning one.
 *
 * If you use something like g_realloc as the allocator, then memory
 * failures become fatal just like in a standard GTK program.
 *
 * Don't change the allocator manually in the buffer_t structure. The
 * _p11_buffer_set_allocator() func will reallocate and handle things
 * properly.
 *
 * Pointers into the Buffer
 *
 * Any write operation has the posibility of reallocating memory
 * and invalidating any direct pointers into the buffer.
 */

/* The allocator for the buffer_t. This follows the realloc() syntax and logic */
typedef void* (*buffer_allocator) (void* p, size_t len);

typedef struct _buffer_t {
	unsigned char *buf;
	size_t len;
	size_t allocated_len;
	int failures;
	buffer_allocator allocator;
} buffer_t;

#define         P11_BUFFER_EMPTY                { NULL, 0, 0, 0, NULL }

int             _p11_buffer_init                (buffer_t *buffer,
                                                 size_t reserve);

int             _p11_buffer_init_full           (buffer_t *buffer,
                                                 size_t reserve,
                                                 buffer_allocator allocator);

void            _p11_buffer_init_static         (buffer_t *buffer,
                                                 const unsigned char *buf,
                                                 size_t len);

void            _p11_buffer_init_allocated      (buffer_t *buffer,
                                                 unsigned char *buf,
                                                 size_t len,
                                                 buffer_allocator allocator);

void            _p11_buffer_uninit              (buffer_t *buffer);

unsigned char * _p11_buffer_uninit_steal        (buffer_t *buffer,
                                                 size_t *n_result);

int             _p11_buffer_set_allocator       (buffer_t *buffer,
                                                 buffer_allocator allocator);

void            _p11_buffer_reset               (buffer_t *buffer);

int             _p11_buffer_equal               (buffer_t *b1,
                                                 buffer_t *b2);

int             _p11_buffer_reserve              (buffer_t *buffer,
                                                 size_t len);

int             _p11_buffer_resize               (buffer_t *buffer,
                                                 size_t len);

int             _p11_buffer_append              (buffer_t *buffer,
                                                 const unsigned char *val,
                                                 size_t len);

unsigned char * _p11_buffer_add_empty           (buffer_t *buffer,
                                                 size_t len);

int             _p11_buffer_add_byte            (buffer_t *buffer,
                                                 unsigned char val);

int             _p11_buffer_get_byte            (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 unsigned char *val);

void            _p11_buffer_encode_uint32       (unsigned char *buf,
                                                 uint32_t val);

uint32_t        _p11_buffer_decode_uint32       (unsigned char *buf);

int             _p11_buffer_add_uint32          (buffer_t *buffer,
                                                 uint32_t val);

int             _p11_buffer_set_uint32          (buffer_t *buffer,
                                                 size_t offset,
                                                 uint32_t val);

int             _p11_buffer_get_uint32          (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 uint32_t *val);

void            _p11_buffer_encode_uint16       (unsigned char *buf,
                                                 uint16_t val);

uint16_t        _p11_buffer_decode_uint16       (unsigned char *buf);

int             _p11_buffer_add_uint16          (buffer_t *buffer,
                                                 uint16_t val);

int             _p11_buffer_set_uint16          (buffer_t *buffer,
                                                 size_t offset,
                                                 uint16_t val);

int             _p11_buffer_get_uint16          (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 uint16_t *val);

int             _p11_buffer_add_byte_array      (buffer_t *buffer,
                                                 const unsigned char *val,
                                                 size_t len);

int             _p11_buffer_get_byte_array      (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 const unsigned char **val,
                                                 size_t *vlen);

int             _p11_buffer_add_string          (buffer_t *buffer,
                                                 const char *str);

int             _p11_buffer_get_string          (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 char **str_ret,
                                                 buffer_allocator allocator);

int             _p11_buffer_add_stringv         (buffer_t *buffer,
                                                 const char **strv);

int             _p11_buffer_get_stringv         (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 char ***strv_ret,
                                                 buffer_allocator allocator);

int             _p11_buffer_add_uint64          (buffer_t *buffer,
                                                 uint64_t val);

int             _p11_buffer_get_uint64          (buffer_t *buffer,
                                                 size_t offset,
                                                 size_t *next_offset,
                                                 uint64_t *val);

#define         _p11_buffer_length(b)           ((b)->len)

#define         _p11_buffer_has_error(b)        ((b)->failures > 0)

#endif /* P11_BUFFER_H */
