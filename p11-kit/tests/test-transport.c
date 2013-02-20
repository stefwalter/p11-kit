/*
 * Copyright (c) 2012 Stefan Walter
 * Copyright (c) 2012 Red Hat Inc.
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
 * Author: Stef Walter <stef@thewalter.net>
 */

#include "config.h"
#include "test.h"

#include "library.h"
#include "mock.h"
#include "path.h"
#include "private.h"
#include "p11-kit.h"
#include "rpc.h"

#include <stdlib.h>

struct {
	char *directory;
	char *user_config;
	char *user_modules;
} test;

static void
setup_remote (void *unused)
{
	const char *data;

	test.directory = p11_test_directory ("p11-test-config");
	test.user_modules = p11_path_build (test.directory, "modules", NULL);
	if (mkdir (test.user_modules, 0700) < 0)
		assert_not_reached ();

	data = "user-config: only\n";
	test.user_config = p11_path_build (test.directory, "pkcs11.conf", NULL);
	p11_test_file_write (NULL, test.user_config, data, strlen (data));

	data = "remote: " SRCDIR "/frob-server " SRCDIR "/.libs/mock-two.so\n";
	p11_test_file_write (test.user_modules, "remote.module", data, strlen (data));

	p11_config_user_modules = test.user_modules;
	p11_config_user_file = test.user_config;
}

static void
teardown_remote (void *unused)
{
	p11_test_directory_delete (test.user_modules);
	p11_test_directory_delete (test.directory);

	free (test.directory);
	free (test.user_config);
	free (test.user_modules);
}

static CK_FUNCTION_LIST *
setup_mock_module (CK_SESSION_HANDLE *session)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_RV rv;
	int i;

	setup_remote (NULL);

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "remote");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	if (session) {
		rv = (module->C_OpenSession) (MOCK_SLOT_ONE_ID, CKF_RW_SESSION | CKF_SERIAL_SESSION,
		                              NULL, NULL, session);
		assert (rv == CKR_OK);
	}

	/* Release all the other modules */
	for (i = 0; modules[i] != NULL; i++) {
		if (modules[i] != module)
			p11_kit_module_release (modules[i]);
	}

	free (modules);
	return module;
}

static void
teardown_mock_module (CK_FUNCTION_LIST *module)
{
	p11_kit_module_finalize (module);
	teardown_remote (NULL);
}

static void
test_basic_exec (void)
{
	CK_FUNCTION_LIST **modules;
	CK_FUNCTION_LIST *module;
	CK_RV rv;

	modules = p11_kit_modules_load (NULL, 0);

	module = p11_kit_module_for_name (modules, "remote");
	assert (module != NULL);

	rv = p11_kit_module_initialize (module);
	assert_num_eq (rv, CKR_OK);

	rv = p11_kit_module_finalize (module);
	assert_num_eq (rv, CKR_OK);

	p11_kit_modules_release (modules);
}

#include "test-mock.c"

int
main (int argc,
      char *argv[])
{
	CK_MECHANISM_TYPE mechanisms[] = {
		CKM_MOCK_CAPITALIZE,
		CKM_MOCK_PREFIX,
		CKM_MOCK_GENERATE,
		CKM_MOCK_WRAP,
		CKM_MOCK_DERIVE,
		CKM_MOCK_COUNT,
		0,
	};

	p11_library_init ();

	/* Override the mechanisms that the RPC mechanism will handle */
	p11_rpc_mechanisms_override_supported = mechanisms;

	p11_fixture (setup_remote, teardown_remote);
	p11_test (test_basic_exec, "/transport/basic");

	test_mock_add_tests ("/transport");

	return  p11_test_run (argc, argv);
}
