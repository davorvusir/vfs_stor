/*·
 * vfs_stor.c
 * Copyright (C) Davor Vusir, 2018
 *
 * 20180323
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
 *  stor:irods_auth_scheme = "PAM"
 * "irods_authentication_scheme": "KRB"
*/

#include <stdio.h>

#include "../source3/include/includes.h"
#include "lib/util/tevent_ntstatus.h"
#include "lib/param/param.h"
#include "lib/param/loadparm.h"
#include "auth.h"
#include "smb.h"
#include "smbd/proto.h"
#include "lib/winbind_util.h"

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


struct vfs_stor {
    struct passwd *act_user;
    rcComm_t *conn;
    rodsEnv env;
    int reconn_flag;
    rErrMsg_t err_msg;
};

static int stor_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
    bool auth_pipe_user_ok = false;
    int status;
    int conn_return = 0;
    uid_t vfs_stor_uid;
    gid_t vfs_stor_gid;
    uint64_t vfs_stor_vuid;
//    uint64_t vfs_stor_vgid;
//    const char *home_dir = NULL;
//    char *vfs_stor_uid2;
//    struct passwd *vfs_stor_passwd;
    char *home_path, *home_path_tmp;
    
    /* iRODS environment */
    struct vfs_stor *stor_data;
    const char *irods_host;
    int irods_port;
    const char *irods_zone_name;
    const char *irods_home, *irods_home_tmp;
    const char *irods_cwd, *irods_cwd_tmp;
    const char *irods_auth_scheme;
    int irods_size_single_buffer;
    int irods_def_trans_threads;
    int irods_transbuf_paratransf;
    int log_level = 1;
    int reconn_flag;
    
    vfs_stor_uid = handle->conn->session_info->unix_token->uid;
    vfs_stor_gid = handle->conn->session_info->unix_token->gid;
    
    DEBUG(1, (__location__ ": cnum[%u], connectpath[%s]\n",
		   (unsigned)handle->conn->cnum,
                    handle->conn->connectpath));

//    status = SMB_VFS_NEXT_CONNECT(handle, service, user);
//	if (status < 0) {
//		return status;
//    }    
 
    stor_data = talloc_zero(handle->conn, struct vfs_stor);
    if (stor_data == NULL) {
        DEBUG(1, ("[VFS_STOR] - talloc_zero - vfs_stor: %s\n",
				"stor_data == NULL\n"));
        errno = ENOMEM;
        return -1;
    }
 
    irods_host = lp_parm_const_string(SNUM(handle->conn),
					"stor", "irods_host",
					"rodsserver.domain.tld");
    irods_port = lp_parm_int(SNUM(handle->conn),
				"stor", "irods_port",
				1247);
    irods_zone_name = lp_parm_const_string(SNUM(handle->conn),
					"stor", "irods_zone_name",
					"Zone needs to be set!");
    irods_home_tmp = lp_parm_const_string(SNUM(handle->conn),
					"stor", "irods_home",
					"rodsHome needs to be set!");
    irods_cwd_tmp = lp_parm_const_string(SNUM(handle->conn),
					"stor", "irods_cwd",
					"rodsCwd needs to be set!");
    irods_auth_scheme = lp_parm_const_string(SNUM(handle->conn),
					"stor", "irods_auth_scheme",
					"native");
    irods_size_single_buffer = lp_parm_int(SNUM(handle->conn),
				"stor", "irods_size_single_buffer",
				32);
    irods_def_trans_threads = lp_parm_int(SNUM(handle->conn),
				"stor", "irods_def_trans_threads",
				4);
    irods_transbuf_paratransf = lp_parm_int(SNUM(handle->conn),
				"stor", "irods_transbuf_paratransf",
				4);
    conn_return = lp_parm_int(SNUM(handle->conn),
				"stor", "conn_return",
				0);
    log_level = lp_parm_int(SNUM(handle->conn),
				"stor", "log_level",
				1);
    
    /* Set iRODS log level */
//    setenv("IRODS_LOG_LEVEL", log_level, 1);
    
    irods_cwd = talloc_strdup_append((char *)irods_cwd_tmp, handle->conn->session_info->unix_info->sanitized_username);
    irods_home = talloc_strdup_append((char *)irods_home_tmp, handle->conn->session_info->unix_info->sanitized_username);
    
    strncpy(stor_data->env.rodsUserName, handle->conn->session_info->unix_info->sanitized_username,
            strlen(handle->conn->session_info->unix_info->sanitized_username));
    strncpy(stor_data->env.rodsHost, irods_host, strlen(irods_host));
    stor_data->env.rodsPort = irods_port;
    strncpy(stor_data->env.rodsZone, irods_zone_name, strlen(irods_zone_name));
    strncpy(stor_data->env.rodsHome, irods_home, strlen(irods_home));
    strncpy(stor_data->env.rodsCwd, irods_cwd, strlen(irods_cwd));
    strncpy(stor_data->env.rodsAuthScheme, irods_auth_scheme, strlen(irods_auth_scheme));
    stor_data->env.irodsMaxSizeForSingleBuffer = irods_size_single_buffer;
    stor_data->env.irodsDefaultNumberTransferThreads = irods_def_trans_threads;
    stor_data->env.irodsTransBufferSizeForParaTrans = irods_transbuf_paratransf;
    
    reconn_flag = NO_RECONN;
    
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsUserName: %s\n",
                            stor_data->env.rodsUserName));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsHost: %s\n",
                            stor_data->env.rodsHost));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsPort: %i\n",
                            stor_data->env.rodsPort));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsZone: %s\n",
                            stor_data->env.rodsZone));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsHome: %s\n",
                            stor_data->env.rodsHome));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsCwd: %s\n",
                            stor_data->env.rodsCwd));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.rodsAuthScheme: %s\n",
                            stor_data->env.rodsAuthScheme));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.irodsMaxSizeForSingleBuffer: %i\n",
                            stor_data->env.irodsMaxSizeForSingleBuffer));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.irodsDefaultNumberTransferThreads: %i\n",
                            stor_data->env.irodsDefaultNumberTransferThreads));
    DEBUG(1, ("[VFS_STOR] - stor_data->env.irodsTransBufferSizeForParaTrans: %i\n",
                            stor_data->env.irodsTransBufferSizeForParaTrans));

    vfs_stor_vuid = get_current_vuid(handle->conn);
    auth_pipe_user_ok = become_user(handle->conn, handle->conn->vuid);
    stor_data->act_user = getpwuid(geteuid());
    
    status = setuid(geteuid());
//    DEBUG(1, ("[VFS_STOR] - seteuid() status: %i\n", status));
    
    DEBUG(1, ("[VFS_STOR] - uid, gid, vuid: %i, %i, %lu\n",
                            vfs_stor_uid, vfs_stor_gid, vfs_stor_vuid));
    DEBUG(1, ("[VFS_STOR] - USER, HOME: %s, %s\n",
                            stor_data->act_user->pw_name,
                            stor_data->act_user->pw_dir));
    setenv("USER", stor_data->act_user->pw_name, 1);
    setenv("HOME", stor_data->act_user->pw_dir, 1);
    DEBUG(1, ("[VFS_STOR] - USER - getenv: %s\n",
                        getenv("USER")));
    DEBUG(1, ("[VFS_STOR] - vfs_stor_uid, vfs_stor_gid: %i, %i\n",
                            vfs_stor_uid, vfs_stor_gid));
    DEBUG(1, ("[VFS_STOR] - HOME - getenv: %s\n",
                        getenv("HOME")));
    DEBUG(1, ("[VFS_STOR] - UID - getenv: %s\n",
                        getenv("UID")));
    DEBUG(1, ("[VFS_STOR] - UID - geteuid(), getuid() = %i, %i\n",
                        geteuid(), getuid()));
    DEBUG(1, ("[VFS_STOR] - char *user: %s\n", user));
    
//    status = getRodsEnvFromEnv(&stor_data->env);
    SMB_VFS_HANDLE_SET_DATA(handle, stor_data, NULL, struct vfs_stor, return -1);
    
//    stor_data->conn = _rcConnect(stor_data->env.rodsHost, stor_data->env.rodsPort,
//                                stor_data->env.rodsUserName, stor_data->env.rodsZone,
//                                NULL, NULL, &stor_data->err_msg, 0, reconn_flag);

    stor_data->conn = rcConnect(stor_data->env.rodsHost, stor_data->env.rodsPort,
                                stor_data->env.rodsUserName, stor_data->env.rodsZone,
                                reconn_flag, &stor_data->err_msg);
    if(stor_data->conn){
        DEBUG(1, ("[VFS_STOR] - stor_data->conn: %s\n",
                            "Tydligen inte NULL!"));
    }
//    SMB_VFS_HANDLE_SET_DATA(handle, stor_data, NULL, struct vfs_stor, return -1);

    /* All OK. */
    return conn_return;

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
//	SMB_VFS_HANDLE_GET_DATA(handle, conn, rcComm_t, return -1);
//	rcDisconnect(conn);
//	SMB_VFS_NEXT_DISCONNECT(handle);
}
