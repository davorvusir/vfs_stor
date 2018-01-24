/*
 * vfs_stor.c
 * Copyright (C) Davor Vusir, 2018
 *
 * Created from Skeleton VFS module.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
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
#include <stdlib.h>
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

struct stor {
        rcComm_t *irods_conn;
        rErrMsg_t errMsg;
//      rodsArguments_t myRodsArgument;
        rodsEnv myEnv;
        int reconnFlag;
};

static int stor_connect(vfs_handle_struct *handle, const char *service,
                        const char *user)
{
        int dvstatus;
        int snum;
        const char *irods_host = NULL;
        int         irods_port = 1247; /* iRODS standard port */
        const char *irods_zone_name = NULL;
        const char *irods_user_name = NULL;
        const char *irods_auth_scheme = NULL;
//      const char *workgroup = NULL;
        const char *home_dir = NULL;
//      char *unix_home_dir;
//      uint_t vuid;
//      rcComm_t *irods_c;

        struct stor *rods_data;
        rods_data = talloc_zero(handle->conn, struct stor);
        if(!rods_data){
                DEBUG(0,("[VFS_stor: talloc_zero() failed\n"));
                return -1;
        }
        SMB_VFS_HANDLE_SET_DATA(handle, rods_data, NULL, struct stor, return -1);
        rods_data->reconnFlag = 0;

        home_dir = handle->conn->session_info->info->home_directory;
        DEBUG(1, ("[VFS_STOR] - home_dir: %s\n", home_dir));
        DEBUG(1, ("[VFS_STOR] - home_directory: %s\n",
                        handle->conn->session_info->info->home_directory));
        setenv("HOME", home_dir, 1);
        home_dir = getenv("HOME");
        DEBUG(1, ("[VFS_STOR] - HOME env var: %s\n", home_dir));

        dvstatus = getRodsEnv(&rods_data->myEnv);
        snum = SNUM(handle->conn);

        irods_host = lp_parm_const_string(snum, "stor", "irods_host", NULL);
        irods_port = lp_parm_int(snum, "stor", "irods_port", 1247);
        irods_zone_name = lp_parm_const_string(snum, "stor", "irods_zone_name", NULL);
        irods_auth_scheme = lp_parm_const_string(snum, "stor", "irods_auth_scheme", NULL);
        irods_user_name = handle->conn->session_info->unix_info->sanitized_username;
//      workgroup = handle->conn->session_info->info->domain_name;
//      rstrcpy(rods_data->myEnv.rodsHost, irods_host, NAME_LEN);
//      rods_data->myEnv.rodsPort = irods_port;
//      strncpy(rods_data->myEnv.rodsUserName, irods_user_name,
//                      strlen(irods_user_name));
//      strncpy(rods_data->myEnv.rodsZone, irods_zone_name,
//                      strlen(irods_zone_name));
//      strncpy(rods_data->myEnv.rodsAuthScheme, irods_auth_scheme,
//                      strlen(irods_auth_scheme));
//      rods_data->myEnv.irodsMaxSizeForSingleBuffer = 32;
//      rods_data->myEnv.irodsDefaultNumberTransferThreads = 4;
//      rods_data->myEnv.irodsTransBufferSizeForParaTrans  = 4;
//      strncpy(rods_data->myEnv.rodsHome, "/tempZone/home/davor", 20);
//      strncpy(rods_data->myEnv.rodsCwd, "/tempZone/home/davor", 20);

//      DEBUG(1, ("[VFS_STOR] irods_host: %s\n", irods_host));
//      DEBUG(1, ("[VFS_STOR] irods_port: %u\n", irods_port));
//      DEBUG(1, ("[VFS_STOR] irods_zone_name: %s\n", irods_zone_name));
//      DEBUG(1, ("[VFS_STOR] myEnv.rodsUserName: %s\n", myEnv.rodsUserName));
//      DEBUG(1, ("[VFS_STOR] myEnv.rodsHost: %s\n", myEnv.rodsHost));
//      DEBUG(1, ("[VFS_STOR] myEnv.rodsPort: %i\n", myEnv.rodsPort));
//      DEBUG(1, ("[VFS_STOR] myEnv.rodsZone: %s\n", myEnv.rodsZone));

//      dvstatus = getRodsEnv(&rods_data->myEnv);
//      DEBUG(1, ("[VFS_STOR] - Före handle->data, irods_host: %s\n", irods_host));
        DEBUG(1, ("[VFS_STOR] - getRodsEnv myEnv.rodsHost: %s\n",
                                        rods_data->myEnv.rodsHost));

        if(dvstatus == 0) {
                DEBUG(1, ("[VFS_STOR] - getRodsEnv, status: %i\n", dvstatus));
                rods_data->irods_conn = rcConnect(rods_data->myEnv.rodsHost,
                                rods_data->myEnv.rodsPort,
                                rods_data->myEnv.rodsUserName,
                                rods_data->myEnv.rodsZone,
                                rods_data->reconnFlag, &(rods_data->errMsg));
        }
        if (rods_data->irods_conn == NULL) {
                DEBUG(1, ("[VFS_STOR] - error rods_data->irods_conn: %s\n",
                                "rods_data->irods_conn == NULL\n"));
                return -1;
        }

        dvstatus = clientLogin(rods_data->irods_conn, 0, irods_auth_scheme);
        DEBUG(1, ("[VFS_STOR] - Efter clientLogin: %i\n", dvstatus));

//      rc = SMB_VFS_NEXT_CONNECT(handle, service, user);

        rcDisconnect(rods_data->irods_conn);
        return dvstatus;
/*
        errno = ENOMEM;
        return -1;
*/
}

