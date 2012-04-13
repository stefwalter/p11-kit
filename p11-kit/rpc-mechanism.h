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

#ifndef _RPC_MECHANISM_H
#define _RPC_MECHANISM_H

#include "pkcs11.h"

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

#endif /* _RPC_MECHANISM_H */
