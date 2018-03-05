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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS


rcComm_t *conn;
rErrMsg_t err_msg;
rodsEnv env;
int reconn_flag;

static bool connect_to_irods(vfs_handle_struct *handle);

static bool connect_to_irods(vfs_handle_struct *handle)
{
    bool connected = false;
    bool auth_pipe_user_ok = false;
    int status = 0;
    uid_t vfs_stor_uid;
    gid_t vfs_stor_gid;
    uint64_t vfs_stor_vuid;
    uint64_t vfs_stor_vgid;
    const char *home_dir = NULL;
    reconn_flag = NO_RECONN;
    
    vfs_stor_uid = handle->conn->session_info->unix_token->uid;
    vfs_stor_gid = handle->conn->session_info->unix_token->gid;
    vfs_stor_vuid = get_current_vuid(handle->conn);
//  become_user_permanently(vfs_stor_uid, vfs_stor_gid);
//  auth_pipe_user_ok = become_authenticated_pipe_user(
//                                        handle->conn->session_info);
    auth_pipe_user_ok = smbd_become_authenticated_pipe_user(
                                            handle->conn->session_info);
    
//    auth_pipe_user_ok = become_user(handle->conn, vfs_stor_vuid);
    DEBUG(1, ("[VFS_STOR] - uid, gid, vuid: %i, %i, %lu\n",
                            vfs_stor_uid, vfs_stor_gid, vfs_stor_vuid));
 
    DEBUG(1, ("[VFS_STOR] - auth_pipe_user_ok = %i\n",
                            auth_pipe_user_ok));
    
    conn = talloc_zero(handle->conn, rcComm_t);
    if(conn){
        vfs_stor_uid = get_current_uid(handle->conn);
        if(auth_pipe_user_ok){
            DEBUG(1, ("[VFS_STOR] - home_dir: %s\n", home_dir));
            DEBUG(1, ("[VFS_STOR] - home_directory: %s\n",
			handle->conn->session_info->info->home_directory));
//          setenv("HOME", home_dir, 1);
            home_dir = getenv("HOME");
            DEBUG(1, ("[VFS_STOR] - HOME env var: %s\n", home_dir));

            /* Read the user's environment file. */
            status = getRodsEnv(&env);
            DEBUG(1, ("[VFS_STOR] - getRodsEnv stor_env.rodsHost: %s\n",
                        	env.rodsHost));
            /* If the reading of the environment went fine, it's time to connect
             * to the iRODS server. */
            if(status == 0) {
                DEBUG(1, ("[VFS_STOR] - getRodsEnv, status: %i\n", status));
                conn = rcConnect(env.rodsHost,
                                    env.rodsPort, env.rodsUserName,
                                    env.rodsZone, reconn_flag,
                                    &err_msg);
                /* rcConnect() -> _rcConnect() -> ... -> sendStartupPack()
                 * -> getRodsEnv()
                 */
                DEBUG(1, ("[VFS_STOR] - getRodsEnv stor_env.rodsHost: %s\n",
                        	env.rodsHost));
 
                }
            }

            if (conn == NULL) {
		DEBUG(1, ("[VFS_STOR] - error iRODS connection: %s\n",
				"data->conn == NULL\n"));
                SMB_VFS_NEXT_DISCONNECT(handle);
                return -1;
            }
            /* We have got a connection. Time to login. */
            status = clientLogin(conn, NO_RECONN, env.rodsAuthScheme);
            DEBUG(1, ("[VFS_STOR] - clientLogin, status: %i\n", status));

            /* Store the connection and associated data to be reused
             * for the reminder of the session. */
            SMB_VFS_HANDLE_SET_DATA(handle, conn, NULL, rcComm_t, return -1);
	}
    
    return connected;
}

static int stor_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
    bool connected = false;
        
    connected = connect_to_irods(handle);
    if(connected)
    {
        DEBUG(1, ("[VFS_STOR] - Connected to iRODS = %i\n",
                            connected));
        return 0;
    } else
    {
        return -1;
    }

/*	This test environment uses the home directory attribute in AD
	(homeDirectory) to get the location of the home directory.
	As Windows cannot interpret POSIX(?) style I have
	used (/data/home/davor). Examine where the smb.conf para-
	meter 'template homedir' is stored. The Samba server, and
	iRODS don't care if it's overridden. The important thing is
	that the users home directory is local to the Samba server for
	this module's iRODS getRodsEnv() to read. Therefore the VFS parameters
	and commented code at the end of this function.
*/
/*	At some time it would be great to create a function that mimics
	iinit to create the users environment file if it's not present.
*/
/*      At some time a translation table between iRODS errors and NT/Samba
	errors has to be created. This error should be returned to the
	Windows client computer.
*/
}

static void stor_disconnect(vfs_handle_struct *handle)
{
        /* User has logged out or disconnected from server. */
	SMB_VFS_HANDLE_GET_DATA(handle, conn, rcComm_t, return -1);
	rcDisconnect(conn);
	SMB_VFS_NEXT_DISCONNECT(handle);
}
