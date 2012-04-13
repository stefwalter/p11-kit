/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/*
   Copyright (C) 2012 Stefan Walter

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

#include "pkcs11.h"
#include "rpc-socket.h"

typedef struct _RpcClientVtable RpcClientVtable;

typedef CK_RV        (*_p11_rpc_client_initialize) (RpcClientVtable *vtable,
                                                    void *init_reserved,
                                                    RpcSocket **socket);

struct _RpcClientVtable {
	void *data;
	_p11_rpc_client_initialize initialize;
};

CK_FUNCTION_LIST_PTR   _p11_rpc_client_register    (const RpcClientVtable *vtable);
