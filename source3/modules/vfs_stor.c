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

#include <stdio.h>

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
//#include "irods/apiPackTable.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct stor_data {
	rcComm_t *irods_conn;
	rErrMsg_t *err_msg;
//	rodsArguments_t myRodsArgument;
	rodsEnv stor_env;
	int reconn_flag;
} *vfs_stor_data;

static int stor_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
	int status;
	int snum;
//	const char *irods_host;
//	int»····    irods_port; /* iRODS standard port */
	const char *home_dir = NULL;
//	rodsEnv init_env;
	rErrMsg_t err_msg;
	
	vfs_stor_data = NULL;
	vfs_stor_data = talloc_zero(handle->conn, struct stor_data);
	if(!vfs_stor_data){
		DEBUG(0,("[VFS_stor: vfs_stor_data = talloc_zero() failed\n"));
		return -1;
	}
	
	vfs_stor_data->reconn_flag = 0;
	
	home_dir = handle->conn->session_info->info->home_directory;
	DEBUG(1, ("[VFS_STOR] - home_dir: %s\n", home_dir));
	DEBUG(1, ("[VFS_STOR] - home_directory: %s\n",
			handle->conn->session_info->info->home_directory));
	setenv("HOME", home_dir, 1);
	home_dir = getenv("HOME");
	DEBUG(1, ("[VFS_STOR] - HOME env var: %s\n", home_dir));
	
	status = getRodsEnv(&vfs_stor_data->stor_env);
//	DEBUG(1, ("[VFS_STOR] - getRodsEnv stor_env.rodsHost: %s\n", init_env.rodsHost));
//	*(vfs_stor_data->stor_env.rodsHost) = talloc_strdup(vfs_stor_data, init_env.rodsHost);
//	vfs_stor_data->stor_env = init_env;
	DEBUG(1, ("[VFS_STOR] - getRodsEnv stor_env.rodsHost: %s\n",
			vfs_stor_data->stor_env.rodsHost));
	
	if(status == 0) {
		DEBUG(1, ("[VFS_STOR] - getRodsEnv, status: %i\n", status));
		vfs_stor_data->irods_conn = rcConnect(
			vfs_stor_data->stor_env.rodsHost,
			vfs_stor_data->stor_env.rodsPort,
			vfs_stor_data->stor_env.rodsUserName,
			vfs_stor_data->stor_env.rodsZone,
			0, &vfs_stor_data->err_msg);
	}
	if (vfs_stor_data->irods_conn == NULL) {
		DEBUG(1, ("[VFS_STOR] - error iRODS connection: %s\n",
				"vfs_stor_data->irods_conn == NULL\n"));
	return -1;
	}
	
	status = clientLogin(vfs_stor_data->irods_conn, 0,
				vfs_stor_data->stor_env.rodsAuthScheme);
	DEBUG(1, ("[VFS_STOR] - Efter clientLogin: %i\n", status));
	
	SMB_VFS_HANDLE_SET_DATA(handle, vfs_stor_data, NULL,
			struct stor, return -1);
	
	snum = SNUM(handle->conn);
	
	
//	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	
	return status;
/*
	errno = ENOMEM;
	return -1;
*/

//	workgroup = handle->conn->session_info->info->domain_name;
//	rstrcpy(rods_data->myEnv.rodsHost, irods_host, NAME_LEN);
//	rods_data->myEnv.rodsPort = irods_port;
//	strncpy(rods_data->myEnv.rodsUserName, irods_user_name,
//			strlen(irods_user_name));
//	strncpy(rods_data->myEnv.rodsZone, irods_zone_name,
//			strlen(irods_zone_name));
//	strncpy(rods_data->myEnv.rodsAuthScheme, irods_auth_scheme,
//			strlen(irods_auth_scheme));
//	rods_data->myEnv.irodsMaxSizeForSingleBuffer = 32;
//	rods_data->myEnv.irodsDefaultNumberTransferThreads = 4;
//	rods_data->myEnv.irodsTransBufferSizeForParaTrans  = 4;
//	strncpy(rods_data->myEnv.rodsHome, "/tempZone/home/davor", 20);
//	strncpy(rods_data->myEnv.rodsCwd, "/tempZone/home/davor", 20);
//	DEBUG(1, ("[VFS_STOR] irods_host: %s\n", irods_host));
//	DEBUG(1, ("[VFS_STOR] irods_port: %u\n", irods_port));
//	DEBUG(1, ("[VFS_STOR] irods_zone_name: %s\n", irods_zone_name));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsUserName: %s\n", myEnv.rodsUserName));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsHost: %s\n", myEnv.rodsHost));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsPort: %i\n", myEnv.rodsPort));
//	DEBUG(1, ("[VFS_STOR] myEnv.rodsZone: %s\n", myEnv.rodsZone));
//	dvstatus = getRodsEnv(&rods_data->myEnv);
//	DEBUG(1, ("[VFS_STOR] - Före handle->data, irods_host: %s\n",
//irods_host));

//	const char *irods_zone_name;
//	const char *irods_user_name;
//	const char *irods_auth_scheme;
//	const char *workgroup = NULL;

//	char *unix_home_dir;
//	uint_t vuid;
//	rcComm_t *irods_c;

//	irods_host = lp_parm_const_string(snum, "stor", "irods_host", NULL);
//	irods_port = lp_parm_int(snum, "stor", "irods_port", 1247);
//	irods_zone_name = lp_parm_const_string(snum, "stor", "irods_zone_name",
//NULL);
//	irods_auth_scheme = lp_parm_const_string(snum, "stor",
//"irods_auth_scheme", NULL);
//	irods_user_name =
//handle->conn->session_info->unix_info->sanitized_username;

}
