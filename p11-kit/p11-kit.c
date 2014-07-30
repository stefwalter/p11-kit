/*
 * Copyright (c) 2011, Collabora Ltd.
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

#include "compat.h"
#include "debug.h"
#include "message.h"
#include "path.h"
#include "p11-kit.h"
#include "remote.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

#include "tool.h"

int       p11_kit_list_modules    (int argc,
                                   char *argv[]);

int       p11_kit_trust           (int argc,
                                   char *argv[]);

int       p11_kit_external        (int argc,
                                   char *argv[]);

int       p11_kit_remote          (int argc,
                                   char *argv[]);

static const p11_tool_command commands[] = {
	{ "list-modules", p11_kit_list_modules, "List modules and tokens" },
	{ "remote", p11_kit_remote, "Run a specific PKCS#11 module remotely" },
	{ P11_TOOL_FALLBACK, p11_kit_external, NULL },
	{ 0, }
};

int
p11_kit_trust (int argc,
               char *argv[])
{
	char **args;

	args = calloc (argc + 2, sizeof (char *));
	return_val_if_fail (args != NULL, 1);

	args[0] = BINDIR "/trust";
	memcpy (args + 1, argv, sizeof (char *) * argc);
	args[argc + 1] = NULL;

	execv (args[0], args);

	/* At this point we have no command */
	p11_message_err (errno, "couldn't run trust tool");

	free (args);
	return 2;
}

int
p11_kit_external (int argc,
                  char *argv[])
{
	char *filename;
	char *path;

	/* These are trust commands, send them to that tool */
	if (strcmp (argv[0], "extract") == 0) {
		return p11_kit_trust (argc, argv);
	} else if (strcmp (argv[0], "extract-trust") == 0) {
		argv[0] = "extract-compat";
		return p11_kit_trust (argc, argv);
	}

	if (asprintf (&filename, "p11-kit-%s", argv[0]) < 0)
		return_val_if_reached (1);

	/* Add our libexec directory to the path */
	path = p11_path_build (PRIVATEDIR, filename, NULL);
	return_val_if_fail (path != NULL, 1);

	argv[argc] = NULL;
	execv (path, argv);

	/* At this point we have no command */
	p11_message ("'%s' is not a valid command. See 'p11-kit --help'", argv[0]);

	free (filename);
	free (path);
	return 2;
}

int
p11_kit_remote (int argc,
                char *argv[])
{
	char *socket_file = NULL;
	CK_FUNCTION_LIST *module;
	uid_t uid = -1, run_as_uid = -1;
	gid_t gid = -1, run_as_gid = -1;
	int opt;
	int ret, e;
	const struct passwd* pwd;
	const struct group* grp;

	enum {
		opt_verbose = 'v',
		opt_help = 'h',
		opt_socket = 's',
		opt_user = 'u',
		opt_group = 'g',
		opt_run_as_user = 'a',
		opt_run_as_group = 'z',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, opt_help },
		{ "socket", required_argument, NULL, opt_socket },
		{ "user", required_argument, NULL, opt_user },
		{ "group", required_argument, NULL, opt_group },
		{ "run-as-user", required_argument, NULL, opt_run_as_user },
		{ "run-as-group", required_argument, NULL, opt_run_as_group },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit remote --help" },
		{ 0, "usage: p11-kit remote <module> -s <socket-file>" },
		{ 0, "usage: p11-kit remote <module> -s <socket-file> -u <allowed-user> -g <allowed-group> --run-as-user <user> --run-as-group <group>" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_socket:
			socket_file = strdup(optarg);
			break;
		case opt_group:
			grp = getgrnam(optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			gid = grp->gr_gid;
			break;
		case opt_user:
			pwd = getpwnam(optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			uid = pwd->pw_uid;
			break;
		case opt_run_as_group:
			grp = getgrnam(optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			run_as_gid = grp->gr_gid;
			break;
		case opt_run_as_user:
			pwd = getpwnam(optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			run_as_uid = pwd->pw_uid;
			break;
		case opt_help:
		case '?':
			p11_tool_usage (usages, options);
			return 0;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (socket_file == NULL) {
		p11_tool_usage (usages, options);
		return 2;
	}

	if (run_as_gid != -1) {
		if (setgid(run_as_gid) == -1) {
			e = errno;
			p11_message("cannot set gid to %u: %s\n", (unsigned)run_as_gid, strerror(e));
			return 1;
		}

		if (setgroups(1, &run_as_gid) == -1) {
			e = errno;
			p11_message("cannot setgroups to %u: %s\n", (unsigned)run_as_gid, strerror(e));
			return 1;
		}
	}

	if (run_as_uid != -1) {
		if (setuid(run_as_uid) == -1) {
			e = errno;
			p11_message("cannot set uid to %u: %s\n", (unsigned)run_as_uid, strerror(e));
			return 1;
		}
	}

	if (argc != 1) {
		p11_message ("specify the module to remote");
		return 2;
	}

	module = p11_kit_module_load (argv[0], 0);
	if (module == NULL)
		return 1;

	ret = p11_kit_remote_serve_module (module, socket_file, uid, gid);
	p11_kit_module_release (module);

	return ret;
}


int
main (int argc,
      char *argv[])
{
	return p11_tool_main (argc, argv, commands);
}
