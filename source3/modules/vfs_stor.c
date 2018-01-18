/*·
 * vfs_stor.c
 * Copyright (C) Davor Vusir, 2018
 *
 * Created from Skeleton VFS module.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *··
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *··
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 *  vfs objects = stor
 *  stor:irods_host = "rods.datadelikatesser.se"
 *  stor:irods_port = 1247
 *  stor:irods_zone_name = "tempZone"
 *  stor:irods_auth_scheme = "KRB"
 * "irods_authentication_scheme": "KRB"
*/

#include <string.h>

#include "../source3/include/includes.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/param/param.h"
#include "lib/param/loadparm.h"
#include "auth.h"
#include "smbd/proto.h"

/* iRODS basics */

#include "irods/rods.h"
#include "irods/getRodsEnv.h"
#include "irods/parseCommandLine.h"
#include "irods/rcMisc.h"
#include "irods/rodsClient.h"
#include "irods/rcConnect.h"
#include "irods/sockComm.h"
#include "irods/stringOpr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct loadparm_context *lp_ctx;
struct auth_usersupplied_info *user_info;

static int stor_connect(vfs_handle_struct *handle, const char *service,
				const char *user)
{
	int dvstatus;
	int snum;
	const char *irods_host = NULL;
	int	irods_port = 1247; /* iRODS standard port */
	const char *irods_zone_name = NULL;
	const char *irods_user_name = NULL;
	const char *irods_auth_scheme = NULL;
//	const char *workgroup = NULL;
	char *home_dir = NULL;
//	uint_t vuid;
	
	rcComm_t *irods_conn = NULL;
	rErrMsg_t *errMsg = NULL;
//	rodsArguments_t myRodsArgument;
	rodsEnv myEnv;
	int reconnFlag = 0;
	
	setenv("HOME", "/data/home/davor", 1);
	home_dir = getenv("HOME");
	DEBUG(1, ("[VFS_STOR] - HOME env var: %s\n", home_dir));
	snum = SNUM(handle->conn);
	
	irods_host = lp_parm_const_string(snum, "stor", "irods_host", NULL);
	irods_port = lp_parm_int(snum, "stor", "irods_port", 1247);
	irods_zone_name = lp_parm_const_string(snum, "stor", "irods_zone_name", NULL);
	irods_auth_scheme = lp_parm_const_string(snum, "stor", "irods_auth_scheme", NULL);
	irods_user_name = handle->conn->session_info->unix_info->sanitized_username;
//	workgroup = handle->conn->session_info->info->domain_name;
	
	DEBUG(1, ("[VFS_STOR] irods_host: %s\n", irods_host));
//	DEBUG(1, ("[VFS_STOR] irods_port: %u\n", irods_port));
//	DEBUG(1, ("[VFS_STOR] irods_zone_name: %s\n", irods_zone_name));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsUserName: %s\n", myEnv.rodsUserName));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsHost: %s\n", myEnv.rodsHost));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsPort: %i\n", myEnv.rodsPort));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsZone: %s\n", myEnv.rodsZone));
	
	dvstatus = getRodsEnv(&myEnv);
//	DEBUG(1, ("[VFS_STOR] - Före handle->data, irods_host: %s\n", irods_host));
	DEBUG(1, ("[VFS_STOR] - getRodsEnv myEnv.rodsHost: %s\n", myEnv.rodsHost));
	if(dvstatus == 0) {
		DEBUG(1, ("[VFS_STOR] - getRodsEnv, status: %i\n", dvstatus));
		handle->data = (rcComm_t *) rcConnect(myEnv.rodsHost,·
							myEnv.rodsPort, myEnv.rodsUserName,·
							myEnv.rodsZone, reconnFlag, &errMsg);
//		DEBUG(1, ("[VFS_STOR] - Efter handle->data, irods_host: %s\n", irods_host));
		DEBUG(1, ("[VFS_STOR] - Efter handle->data, myEnv.rodsHost: %s\n", myEnv.rodsHost));
	}
	if (handle->data == NULL) {
		DEBUG(1, ("[VFS_STOR] - error handle-data: %s\n", "handle->data == NULL\n"));
		return -1;
	}
	
	dvstatus = clientLogin(handle->data, 0, irods_auth_scheme);
	DEBUG(1, ("[VFS_STOR] - Efter clientLogin: %i\n", dvstatus));
	
//	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	
	if (dvstatus < 0) {
		rcDisconnect(handle->data);
		return dvstatus;
	}
	return 0;
/*
	errno = ENOMEM;
	return -1;
*/
}
