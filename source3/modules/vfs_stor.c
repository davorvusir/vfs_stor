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
	rcComm_t *conn;
	rErrMsg_t err_msg;
//	rodsArguments_t myRodsArgument;
	rodsEnv env;
	int reconn_flag;
};

static int stor_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
	int status;
//	int snum;
//	const char *irods_host;
//	int»····    irods_port; /* iRODS standard port */
	const char *home_dir = NULL;
	
	struct stor_data *data = NULL;
//	rErrMsg_t err_msg = { 0 };
	
	data = talloc_zero(handle->conn, struct stor_data);
	if(!data){
		DEBUG(0,("[VFS_stor: data = talloc_zero() failed\n"));
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}
	
	data->reconn_flag = NO_RECONN;
	
/*»·····This test environment uses the home directory attribute in AD
	(homeDirectory) to get the location of the home directory.
	As Windows cannot interpret POSIX(?) style I have
	used (/data/home/davor). Examine where the smb.conf para-
	meter 'template homedir' is stored. The Samba server, and
	iRODS don't care if it's overridden. The important thing is
	that the users home directory is local to the Samba server for
	this module's iRODS getRodsEnv() to read. Therefore the VFS parameters
	and commented code at the end of this function.
*/
	home_dir = handle->conn->session_info->info->home_directory;
	DEBUG(1, ("[VFS_STOR] - home_dir: %s\n", home_dir));
	DEBUG(1, ("[VFS_STOR] - home_directory: %s\n",
			handle->conn->session_info->info->home_directory));
	setenv("HOME", home_dir, 1);
	home_dir = getenv("HOME");
	DEBUG(1, ("[VFS_STOR] - HOME env var: %s\n", home_dir));
	
/*»·····At some time it would be great to create a function that mimics
	iinit to create the users environment file if it's not present.
	An embryo is in the commented code at the end of this function.
*/
	/* Read the users environment file. */
	status = getRodsEnv(&data->env);
	DEBUG(1, ("[VFS_STOR] - getRodsEnv stor_env.rodsHost: %s\n",
			data->env.rodsHost));
	
	/* If the reading of the environment went fine, it's time to connect
	   to the iRODS server. */
	if(status == 0) {
		DEBUG(1, ("[VFS_STOR] - getRodsEnv, status: %i\n", status));
		data->conn = rcConnect(data->env.rodsHost,
				data->env.rodsPort, data->env.rodsUserName,
				data->env.rodsZone, data->reconn_flag,
				&data->err_msg);
	}
	if (data->conn == NULL) {
		DEBUG(1, ("[VFS_STOR] - error iRODS connection: %s\n",
				"data->conn == NULL\n"));
	return -1;
	}
	
	/* We have got a connection. Time to login. */
	status = clientLogin(data->conn, NO_RECONN, data->env.rodsAuthScheme);
	DEBUG(1, ("[VFS_STOR] - Efter clientLogin: %i\n", status));
	
	/* Store the connection and associated data to be reused
	   for the reminder of the session. */
	SMB_VFS_HANDLE_SET_DATA(handle, data, NULL, struct stor, return -1);
	
//	snum = SNUM(handle->conn);
	
	
//	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	
/*»·····At some time a translation table between iRODS errors and NT/Samba
	errors has to be created. This error should be returned to the
	Windows client computer.
*/
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

static void stor_disconnect(vfs_handle_struct *handle)
{
	struct stor_data *data = NULL;
	
	SMB_VFS_HANDLE_GET_DATA(handle, data, struct stor_data, return -1);
	rcDisconnect(data->conn);
	SMB_VFS_NEXT_DISCONNECT(handle);
}
