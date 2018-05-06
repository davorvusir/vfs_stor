/*·
 * vfs_stor.c
 * Copyright (C) Davor Vusir, 2018
 *
 * 20180506
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

#include "includes.h"
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
#include "irods/miscUtil.h"
#include "irods/rodsClient.h"
#include "irods/rcConnect.h"
#include "irods/sockComm.h"
#include "irods/stringOpr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* One appealing idea is to use DatabaseFS as a template for presenting a
 * directory or file. see https://github.com/ZeWaren/DatabaseFS or maybe it is
 * better to gather the handle and entry in a separate struct.
 * And extend (or copy) the result to struct files_struct. That way I hope that
 * the SQL querys and other iRODS specifics get a natural presentation to
 * Windows/SMB client.
 * See
 * https://wiki.samba.org/index.php/Writing_a_Samba_VFS_Module#Extending_the_Samba_files_struct_structure
 * and
 * https://github.com/samba-team/samba/blob/v4-7-stable/source3/include/vfs.h#L298 */
struct stor_file {
    collHandle_t *coll_handle;   /* Handle to iRODS collection */
    collEnt_t *coll_ent;         /* Equivalent to a directory or file? */
 
};

struct stor_data {
    /* iRODS specific */
    rcComm_t *stor_conn;	/* ICAT database connection handle */
    rodsEnv env;		/* User's connection information */
    rErrMsg_t err_msg;
    int reconn_flag;
/*    collHandle_t *coll_handle;    Handle to iRODS collection */
/*    collEnt_t *coll_ent;          Equivalent to a directory or file? */
    
/* "Samba/SMB specific" */
/*  char path_prefix[MAX_NAME_LEN];	local (to server) path prefix
					(path in smb.conf) or user's
					stor_data->rodsHome[] when 
					first connected */	
								
};

struct passwd *act_user;

static int stor_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
    int status;
    int conn_return;
    uid_t vfs_stor_uid;
    gid_t vfs_stor_gid;
//    uint64_t vfs_stor_vuid;
    TALLOC_CTX *mem_ctx = talloc_tos();
    TALLOC_CTX *initial_path_ctx = talloc_tos();
    char *tmp_user_home;
    struct smb_filename *initial_path;
    struct stor_data *rods = NULL;
    
    DEBUG(1, (__location__ ": cnum[%u], connectpath[%s]\n",
		   (unsigned)handle->conn->cnum,
                    handle->conn->connectpath));
    
//    rods->stor_conn = NULL;
//    rods->reconn_flag = NO_RECONN;
    status = 0; /* Assume connection is successful. */
    conn_return = 0;
    
    vfs_stor_uid = handle->conn->session_info->unix_token->uid;
    vfs_stor_uid = get_current_uid(handle->conn);
    vfs_stor_gid = handle->conn->session_info->unix_token->gid;
    act_user = Get_Pwnam_alloc(mem_ctx, user);
    tmp_user_home = get_user_home_dir(mem_ctx, user);
    DEBUG(1, ("[VFS_STOR], act_user - pw_uid, pw_gid, pw_name: %i, %i, %s\n",
                            act_user->pw_uid, act_user->pw_gid, act_user->pw_name));
    setenv("HOME", tmp_user_home, 1);
    setenv("USER", act_user->pw_name, 1);
    setenv("LOGNAME", act_user->pw_name, 1);

/* https://github.com/samba-team/samba/blob/master/docs-xml/Samba-Developers-Guide/vfs.xml
    SMB_VFS_OPAQUE_OPEN(conn, fname, flags, mode);
 */
    rods = talloc_zero(handle->conn, struct stor_data);
    if (rods == NULL) {
        conn_return = -1;
        DEBUG(1, ("[VFS_STOR] - talloc_zero - vfs_stor: %s\n",
				"rods == NULL\n"));
        errno = ENOMEM;
        return conn_return;
//        return -1;
    }
    
    rods->stor_conn = NULL;
    
    status = getRodsEnv(&rods->env);
    if (status == 0){
        rods->stor_conn = rcConnect(rods->env.rodsHost, rods->env.rodsPort,
                          rods->env.rodsUserName,
                          rods->env.rodsZone, rods->reconn_flag, &rods->err_msg);
    	
	DEBUG(1, ("[VFS_STOR] -  connection to zone established: %s\n",
                                "rcConnect() succeded.\n"));
/*
        DEBUG(1, ("[VFS_STOR] -  env.rodsHost: %s\n",
                                env.rodsHost));
        DEBUG(1, ("[VFS_STOR] -  env.rodsAuthScheme: %s\n",
                                env.rodsAuthScheme));
        
        DEBUG(1, ("[VFS_STOR] -  authInfo.authFlag: %i\n",
                                stor_conn->clientUser.authInfo.authFlag));
        DEBUG(1, ("[VFS_STOR] -  authInfo.authScheme: %s\n",
                                stor_conn->clientUser.authInfo.authScheme));
        DEBUG(1, ("[VFS_STOR] -  authInfo.authStr: %s\n",
                                stor_conn->clientUser.authInfo.authStr));
        DEBUG(1, ("[VFS_STOR] -  authInfo.host: %s\n",
                                stor_conn->clientUser.authInfo.host));
        DEBUG(1, ("[VFS_STOR] -  authInfo.ppid: %i\n",
                                stor_conn->clientUser.authInfo.ppid));
        rstrcpy(stor_conn->clientUser.authInfo.authScheme, env.rodsAuthScheme,
                       MAX_NAME_LEN);
        rstrcpy(stor_conn->clientUser.authInfo.host, env.rodsHost,
                       MAX_NAME_LEN);
*/        
        /* 
         * This is set by clientLogin() when an iCommand is run.
         * Might be useful.
         */
        rods->stor_conn->loggedIn = 1;
    
    } else {
        status = -1;
        DEBUG(1, ("[VFS_STOR] - could not rcConnect(): %s\n",
				"getRodsEnv() failed.\n"));
        errno = ENOMEM;
        return status;
    }

    if(rods != NULL){
      SMB_VFS_HANDLE_SET_DATA(handle, rods, NULL, struct stor_data, return -1);
//        handle->conn->connectpath = talloc_strdup_append(handle->conn->connectpath,
//                                            env.rodsCwd);
//        initial_path = synthetic_smb_fname(initial_path_ctx, env.rodsCwd,
//                                            NULL, NULL, 0);
//        handle->conn->connectpath = talloc_strdup_append(handle->conn->connectpath,
//                                            initial_path->base_name);
        DEBUG(1, (__location__ ": cnum[%u], connectpath[%s]\n",
		   (unsigned)handle->conn->cnum,
                    handle->conn->connectpath));
//        handle->data = rods;

        /* All OK. */
        return status;

    } else {
        status = -1;
        DEBUG(1, ("[VFS_STOR] - could not rcConnect(): %i, %s\n",
				rods->err_msg.status, rods->err_msg.msg));
        errno = ENOMEM;
        return status;
    }
//    return -1;
    
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
    struct stor_data *rods_disconn = NULL;
    
    /* User has logged out or disconnected from server. */
    SMB_VFS_HANDLE_GET_DATA(handle, rods_disconn, struct stor_data, return -1);
    rcDisconnect(rods_disconn->stor_conn);
//    SMB_VFS_NEXT_DISCONNECT(handle);
}

/*
static int connect_to_irods(vfs_handle_struct *handle, const char *user);

static int connect_to_irods(vfs_handle_struct *handle, const char *user){
    bool auth_pipe_user_ok = false;
    int status;
    int conn_return = 0;
    uid_t vfs_stor_uid;
    gid_t vfs_stor_gid;
    uint64_t vfs_stor_vuid;
    uint64_t vfs_stor_vgid;
    const char *home_dir = NULL;
    char *vfs_stor_uid2;
    connection_struct *conn = handle->conn;
    TALLOC_CTX *mem_ctx = talloc_tos();
    char *tmp_user;
    
  
    stor_conn = NULL;
    reconn_flag = NO_RECONN;
    
    vfs_stor_uid = handle->conn->session_info->unix_token->uid;
    vfs_stor_uid = get_current_uid(handle->conn);
    vfs_stor_gid = handle->conn->session_info->unix_token->gid;
    vfs_stor_vuid = get_current_vuid(handle->conn);
    auth_pipe_user_ok = become_user(handle->conn, handle->conn->vuid);
    
    status = getRodsEnv(&env);
    DEBUG(1, ("[VFS_STOR], getRodsEnv(): %i\n", status));

    DEBUG(1, ("[VFS_STOR], cti - uid, gid, vuid: %i, %i, %lu\n",
                            vfs_stor_uid, vfs_stor_gid, vfs_stor_vuid));
    DEBUG(1, ("[VFS_STOR] - getRodsEnvStatus: %i\n", status));
    DEBUG(1, ("[VFS_STOR] - env.rodsUserName: %s\n",
                            env.rodsUserName));
    DEBUG(1, ("[VFS_STOR] - env.rodsHost: %s\n",
                            env.rodsHost));
    stor_conn = rcConnect(env.rodsHost, env.rodsPort,
                          handle->conn->session_info->unix_info->sanitized_username,
                          env.rodsZone, reconn_flag, &err_msg);

    DEBUG(1, ("[VFS_STOR] - cti->env.rodsHost: %s\n",
                            cti->env.rodsHost));
    DEBUG(1, ("[VFS_STOR] - cti->env.rodsPort: %i\n",
                            cti->env.rodsPort));
    DEBUG(1, ("[VFS_STOR] - cti->env.rodsZone: %s\n",
    cti->env.rodsZone));
    DEBUG(1, ("[VFS_STOR] - cti->env.rodsHome: %s\n",
                            cti->env.rodsHome));
    DEBUG(1, ("[VFS_STOR] - cti->env.rodsCwd: %s\n",
                            cti->env.rodsCwd));
    DEBUG(1, ("[VFS_STOR] - cti->env.rodsAuthScheme: %s\n",
                            cti->env.rodsAuthScheme));
    DEBUG(1, ("[VFS_STOR] - cti->env.irodsMaxSizeForSingleBuffer: %i\n",
                            cti->env.irodsMaxSizeForSingleBuffer));
    DEBUG(1, ("[VFS_STOR] - cti->env.irodsDefaultNumberTransferThreads: %i\n",
                            cti->env.irodsDefaultNumberTransferThreads));
    DEBUG(1, ("[VFS_STOR] - cti->env.irodsTransBufferSizeForParaTrans: %i\n",
                            cti->env.irodsTransBufferSizeForParaTrans));
    
    vfs_stor_vuid = get_current_vuid(handle->conn);
    auth_pipe_user_ok = become_user(handle->conn, handle->conn->vuid);
    auth_pipe_user_ok = become_user(handle->conn, get_current_vuid(handle->conn));
    become_user_permanently(vfs_stor_uid, vfs_stor_gid);
    status = setuid(geteuid());
    auth_pipe_user_ok = change_to_user(handle->conn, vfs_stor_vuid);
    act_user = getpwuid(vfs_stor_uid);
    DEBUG(1, ("[VFS_STOR], act_user - pw_uid, pw_gid: %i, %i\n",
                            act_user->pw_uid, act_user->pw_gid));
    cti->act_user = getpwnam(handle->conn->session_info->unix_info->sanitized_username);
    if(act_user == NULL){
        DEBUG(1, ("[VFS_STOR], cti - couldn't allocate a passwd struct: %i\n", -1));
    } else {
        if ((status = setgid(vfs_stor_gid)) != 0){
            DEBUG(1, ("[VFS_STOR], cti - couldn't setgid(): %i\n", status));
        } else {
            if ((status = setuid(act_user->pw_uid)) != 0){
                DEBUG(1, ("[VFS_STOR], act_user - couldn't setuid: %i\n", status));
            } else {
                DEBUG(1, ("[VFS_STOR], act_user - USER - getenv after setuid: %s\n",
                        getenv("USER")));
                DEBUG(1, ("[VFS_STOR], cti - LOGNAME - getenv after setuid: %s\n",
                        getenv("LOGNAME")));
                tmp_user = get_user_home_dir(mem_ctx, user);
                setenv("HOME", tmp_user, 1);
                setenv("USER", act_user->pw_name, 1);
                setenv("LOGNAME", act_user->pw_name, 1);
                
                DEBUG(1, ("[VFS_STOR], HOME - getenv after setenv: %s\n",
                        getenv("HOME")));
                DEBUG(1, ("[VFS_STOR], cti - USER - act_user->pw_name: %s\n",
                        act_user->pw_name));
                DEBUG(1, ("[VFS_STOR], USER - getenv after setenv: %s\n",
                        getenv("USER")));
                DEBUG(1, ("[VFS_STOR], LOGNAME - getenv after setenv: %s\n",
                        getenv("LOGNAME")));

                status = getRodsEnv(&env);
                DEBUG(1, ("[VFS_STOR], getRodsEnv(): %i\n", status));

                become_user(conn, handle->conn->vuid);
                    
                change_to_root_user();
                become_root();
                status = getRodsEnv(&cti->env);
                unbecome_root();
                cti->conn = rcConnect(cti->env.rodsHost, cti->env.rodsPort,
                                cti->env.rodsUserName, cti->env.rodsZone,
                                reconn_flag, &(cti)->err_msg);
                
                unbecome_root();
                become_user_permanently(vfs_stor_uid, vfs_stor_gid);
                DEBUG(1, ("[VFS_STOR], cti - Efter rcConnect(): %s\n",
                        "NULLO"));

            }
        }
    }

    status = setuid(geteuid());
    DEBUG(1, ("[VFS_STOR] - seteuid() status: %i\n", status));
    
    DEBUG(1, ("[VFS_STOR], cti - uid, gid, vuid: %i, %i, %lu\n",
                            vfs_stor_uid, vfs_stor_gid, vfs_stor_vuid));
    DEBUG(1, ("[VFS_STOR], cti - USER, HOME: %s, %s\n",
                            cti->act_user->pw_name,
                            cti->act_user->pw_dir));
    setenv("USER", cti->act_user->pw_name, 1);
    setenv("LOGNAME", cti->act_user->pw_name, 1);
    setenv("HOME", cti->act_user->pw_dir, 1);
    setenv("SHELL", cti->act_user->pw_shell, 1);
    DEBUG(1, ("[VFS_STOR], cti - USER - getenv after setenv: %s\n",
                        getenv("USER")));
    DEBUG(1, ("[VFS_STOR], cti - LOGNAME - getenv after setenv: %s\n",
                        getenv("LOGNAME")));
    DEBUG(1, ("[VFS_STOR], cti - vfs_stor_uid, vfs_stor_gid: %i, %i\n",
                            vfs_stor_uid, vfs_stor_gid));
    DEBUG(1, ("[VFS_STOR], cti - HOME - getenv after setenv: %s\n",
                        getenv("HOME")));
    DEBUG(1, ("[VFS_STOR], cti - UID - geteuid(), getuid() = %i, %i\n",
                        geteuid(), getuid()));
 
    vfs_stor_vuid = get_current_vuid(handle->conn);
    change_to_user_internal(handle->conn, handle->conn->session_info,
                            vfs_stor_vuid);
act_user = Get_Pwnam_alloc(mem_ctx, user);
setenv("HOME", act_user->pw_dir, 1);
setenv("USER", act_user->pw_name, 1);
setenv("LOGNAME", act_user->pw_name, 1);
    status = getRodsEnv(&env);
    DEBUG(1, ("[VFS_STOR], getRodsEnv(): %i\n", status));

    DEBUG(1, ("[VFS_STOR], cti - uid, gid, vuid: %i, %i, %lu\n",
                            vfs_stor_uid, vfs_stor_gid, vfs_stor_vuid));
    DEBUG(1, ("[VFS_STOR] - env.rodsUserName: %s\n",
                            env.rodsUserName));
    DEBUG(1, ("[VFS_STOR] - HOME: %s\n", getenv("HOME")));
    DEBUG(1, ("[VFS_STOR] - LOGNAME: %s\n", getenv("LOGNAME")));
    DEBUG(1, ("[VFS_STOR] - env.rodsHost: %s\n",
                            env.rodsHost));
    stor_conn = rcConnect(env.rodsHost, env.rodsPort,
                          act_user->pw_name,
                          env.rodsZone, reconn_flag, &err_msg);

    if(stor_conn != NULL){
        DEBUG(1, ("[VFS_STOR], cti - cti->conn: %s\n",
                            "Tydligen inte NULL!"));
        unbecome_user();
        return 0;
    }
    unbecome_user();
    return 0;
 } //END - connect_to_irods
*/

static uint64_t stor_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	*bsize = 0;
	*dfree = 0;
	*dsize = 0;
	return 0;
}

static int stor_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

static int stor_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
			  unid_t id, SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

static int stor_get_shadow_copy_data(vfs_handle_struct *handle,
				     files_struct *fsp,
				     struct shadow_copy_data *shadow_copy_data,
				     bool labels)
{
	errno = ENOSYS;
	return -1;
}

static int stor_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf)
{
	errno = ENOSYS;
	return -1;
}

static uint32_t stor_fs_capabilities(struct vfs_handle_struct *handle,
				     enum timestamp_set_resolution *p_ts_res)
{
	return 0;
}

static NTSTATUS stor_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static DIR *stor_opendir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *mask,
			uint32_t attr)
{
	return NULL;
}

static NTSTATUS stor_snap_check_path(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     const char *service_path,
				     char **base_volume)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS stor_snap_create(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 const char *base_volume,
				 time_t *tstamp,
				 bool rw,
				 char **base_path,
				 char **snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS stor_snap_delete(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 char *base_path,
				 char *snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static DIR *stor_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
			   const char *mask, uint32_t attr)
{
	return NULL;
}

static struct dirent *stor_readdir(vfs_handle_struct *handle,
				   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	return NULL;
}

static void stor_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
	;
}

static long stor_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	return (long)-1;
}

static void stor_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	;
}

static int stor_mkdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int stor_rmdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int stor_closedir(vfs_handle_struct *handle, DIR *dir)
{
	errno = ENOSYS;
	return -1;
}

static void stor_init_search_op(struct vfs_handle_struct *handle, DIR *dirp)
{
	;
}

static int stor_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
		     files_struct *fsp, int flags, mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static NTSTATUS stor_create_file(struct vfs_handle_struct *handle,
				 struct smb_request *req,
				 uint16_t root_dir_fid,
				 struct smb_filename *smb_fname,
				 uint32_t access_mask,
				 uint32_t share_access,
				 uint32_t create_disposition,
				 uint32_t create_options,
				 uint32_t file_attributes,
				 uint32_t oplock_request,
				 struct smb2_lease *lease,
				 uint64_t allocation_size,
				 uint32_t private_flags,
				 struct security_descriptor *sd,
				 struct ea_list *ea_list,
				 files_struct **result, int *pinfo,
				 const struct smb2_create_blobs *in_context_blobs,
				 struct smb2_create_blobs *out_context_blobs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int stor_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_vfs_read(vfs_handle_struct *handle, files_struct *fsp,
			     void *data, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_pread(vfs_handle_struct *handle, files_struct *fsp,
			  void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *stor_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
	return NULL;
}

static ssize_t stor_pread_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static ssize_t stor_write(vfs_handle_struct *handle, files_struct *fsp,
			  const void *data, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			   const void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *stor_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
	return NULL;
}

static ssize_t stor_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static off_t stor_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
	errno = ENOSYS;
	return (off_t) - 1;
}

static ssize_t stor_sendfile(vfs_handle_struct *handle, int tofd,
			     files_struct *fromfsp, const DATA_BLOB *hdr,
			     off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_recvfile(vfs_handle_struct *handle, int fromfd,
			     files_struct *tofsp, off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static int stor_rename(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname_src,
		       const struct smb_filename *smb_fname_dst)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fsync(vfs_handle_struct *handle, files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *stor_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
	return NULL;
}

static int stor_fsync_recv(struct tevent_req *req,
			   struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static int stor_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fstat(vfs_handle_struct *handle, files_struct *fsp,
		      SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

static int stor_lstat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static uint64_t stor_get_alloc_size(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

static int stor_unlink(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int stor_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fchmod(vfs_handle_struct *handle, files_struct *fsp,
		       mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int stor_chown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fchown(vfs_handle_struct *handle, files_struct *fsp,
		       uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int stor_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int stor_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
/*
         int status;
        
        rodsArguments_t myRodsArgs;
        rodsPath_t rodsPath;
        
        memset( ( char* )&rodsPath, 0, sizeof( rodsPath ) );
        rstrcpy( rodsPath.inPath, env.rodsCwd, MAX_NAME_LEN );
        parseRodsPath( &rodsPath, &env );
        
        init_client_api_table();
        status = getRodsObjType( handle->data->stor_conn, &rodsPath );
        
//        handle->conn->connectpath = rodsPath.inPath;
        handle->conn->connectpath = talloc_strdup_append(handle->conn->connectpath,
                                            handle->data->env.rodsCwd);
        DBG_DEBUG("[VFS_STOR] chdir(%p) = %s\n", handle, handle->conn->connectpath);
//        DEBUG(1, (__location__ ": cnum[%u], connectpath[%s]\n",
//		   (unsigned)handle->conn->cnum,
//                    handle->conn->connectpath));
    
        return status;
*/
	errno = ENOSYS;
	return -1;
 

}

static struct smb_filename *stor_getwd(vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
/*
     const char *cwd = handle->data->env.rodsCwd;
    
    DBG_DEBUG("[VFS_STOR] getwd(%p) = %s\n", handle, cwd);
    return synthetic_smb_fname(ctx, cwd, NULL, NULL, 0);
*/
        errno = ENOSYS;
	return NULL;

}

static int stor_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
	errno = ENOSYS;
	return -1;
}

static int stor_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
			  off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			  uint32_t mode, off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}

static bool stor_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
		      off_t offset, off_t count, int type)
{
	errno = ENOSYS;
	return false;
}

static int stor_kernel_flock(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     uint32_t share_mode, uint32_t access_mask)
{
	errno = ENOSYS;
	return -1;
}

static int stor_linux_setlease(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, int leasetype)
{
	errno = ENOSYS;
	return -1;
}

static bool stor_getlock(vfs_handle_struct *handle, files_struct *fsp,
			 off_t *poffset, off_t *pcount, int *ptype,
			 pid_t *ppid)
{
	errno = ENOSYS;
	return false;
}

static int stor_symlink(vfs_handle_struct *handle,
			const char *link_contents,
			const struct smb_filename *new_smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int stor_vfs_readlink(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	errno = ENOSYS;
	return -1;
}

static int stor_link(vfs_handle_struct *handle,
			const struct smb_filename *old_smb_fname,
			const struct smb_filename *new_smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int stor_mknod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	errno = ENOSYS;
	return -1;
}

static struct smb_filename *stor_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return NULL;
}

static int stor_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uint flags)
{
	errno = ENOSYS;
	return -1;
}

static struct file_id stor_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id;
	ZERO_STRUCT(id);
	errno = ENOSYS;
	return id;
}

struct stor_offload_read_state {
	bool dummy;
};

static struct tevent_req *stor_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)
{
	struct tevent_req *req = NULL;
	struct stor_offload_read_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct stor_offload_read_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS stor_offload_read_recv(struct tevent_req *req,
				       struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB *_token_blob)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}

struct stor_cc_state {
	uint64_t unused;
};

static struct tevent_req *stor_offload_write_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       uint32_t fsctl,
					       DATA_BLOB *token,
					       off_t transfer_offset,
					       struct files_struct *dest_fsp,
					       off_t dest_off,
					       off_t num)
{
	struct tevent_req *req;
	struct stor_cc_state *cc_state;

	req = tevent_req_create(mem_ctx, &cc_state, struct stor_cc_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS stor_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}

static NTSTATUS stor_get_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     struct smb_filename *smb_fname,
				     uint16_t *_compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS stor_set_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     uint16_t compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS stor_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int stor_get_real_filename(struct vfs_handle_struct *handle,
				  const char *path,
				  const char *name,
				  TALLOC_CTX *mem_ctx, char **found_name)
{
	errno = ENOSYS;
	return -1;
}

static const char *stor_connectpath(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
/*        
        errno = ENOSYS;
	return NULL;
*/
}

static NTSTATUS stor_brl_lock_windows(struct vfs_handle_struct *handle,
				      struct byte_range_lock *br_lck,
				      struct lock_struct *plock,
				      bool blocking_lock)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static bool stor_brl_unlock_windows(struct vfs_handle_struct *handle,
				    struct messaging_context *msg_ctx,
				    struct byte_range_lock *br_lck,
				    const struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static bool stor_brl_cancel_windows(struct vfs_handle_struct *handle,
				    struct byte_range_lock *br_lck,
				    struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static bool stor_strict_lock_check(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static NTSTATUS stor_translate_name(struct vfs_handle_struct *handle,
				    const char *mapped_name,
				    enum vfs_translate_direction direction,
				    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_fsctl(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   TALLOC_CTX *ctx,
			   uint32_t function,
			   uint16_t req_flags,	/* Needed for UNICODE ... */
			   const uint8_t *_in_data,
			   uint32_t in_len,
			   uint8_t **_out_data,
			   uint32_t max_out_len, uint32_t *out_len)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_readdir_attr(struct vfs_handle_struct *handle,
				  const struct smb_filename *fname,
				  TALLOC_CTX *mem_ctx,
				  struct readdir_attr_data **pattr_data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_get_dos_attributes(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_fget_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_set_dos_attributes(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_fset_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_get_nt_acl(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS stor_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info_sent,
				 const struct security_descriptor *psd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int stor_chmod_acl(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp,
			   mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static SMB_ACL_T stor_sys_acl_get_file(vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

static SMB_ACL_T stor_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

static int stor_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int stor_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp, TALLOC_CTX *mem_ctx,
				    char **blob_description, DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int stor_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

static int stor_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

static int stor_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_listxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t stor_flistxattr(vfs_handle_struct *handle,
			       struct files_struct *fsp, char *list,
			       size_t size)
{
	errno = ENOSYS;
	return -1;
}

static int stor_removexattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fremovexattr(vfs_handle_struct *handle,
			     struct files_struct *fsp, const char *name)
{
	errno = ENOSYS;
	return -1;
	return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int stor_setxattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			const void *value,
			size_t size,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

static int stor_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	errno = ENOSYS;
	return -1;
}

static bool stor_aio_force(struct vfs_handle_struct *handle,
			   struct files_struct *fsp)
{
	errno = ENOSYS;
	return false;
}

/* VFS operations structure */

struct vfs_fn_pointers stor_fns = {
	/* Disk operations */

	.connect_fn = stor_connect,
	.disconnect_fn = stor_disconnect,
	.disk_free_fn = stor_disk_free,
	.get_quota_fn = stor_get_quota,
	.set_quota_fn = stor_set_quota,
	.get_shadow_copy_data_fn = stor_get_shadow_copy_data,
	.statvfs_fn = stor_statvfs,
	.fs_capabilities_fn = stor_fs_capabilities,
	.get_dfs_referrals_fn = stor_get_dfs_referrals,
	.snap_check_path_fn = stor_snap_check_path,
	.snap_create_fn = stor_snap_create,
	.snap_delete_fn = stor_snap_delete,

	/* Directory operations */

	.opendir_fn = stor_opendir,
	.fdopendir_fn = stor_fdopendir,
	.readdir_fn = stor_readdir,
	.seekdir_fn = stor_seekdir,
	.telldir_fn = stor_telldir,
	.rewind_dir_fn = stor_rewind_dir,
	.mkdir_fn = stor_mkdir,
	.rmdir_fn = stor_rmdir,
	.closedir_fn = stor_closedir,
	.init_search_op_fn = stor_init_search_op,

	/* File operations */

	.open_fn = stor_open,
	.create_file_fn = stor_create_file,
	.close_fn = stor_close_fn,
	.read_fn = stor_vfs_read,
	.pread_fn = stor_pread,
	.pread_send_fn = stor_pread_send,
	.pread_recv_fn = stor_pread_recv,
	.write_fn = stor_write,
	.pwrite_fn = stor_pwrite,
	.pwrite_send_fn = stor_pwrite_send,
	.pwrite_recv_fn = stor_pwrite_recv,
	.lseek_fn = stor_lseek,
	.sendfile_fn = stor_sendfile,
	.recvfile_fn = stor_recvfile,
	.rename_fn = stor_rename,
	.fsync_fn = stor_fsync,
	.fsync_send_fn = stor_fsync_send,
	.fsync_recv_fn = stor_fsync_recv,
	.stat_fn = stor_stat,
	.fstat_fn = stor_fstat,
	.lstat_fn = stor_lstat,
	.get_alloc_size_fn = stor_get_alloc_size,
	.unlink_fn = stor_unlink,
	.chmod_fn = stor_chmod,
	.fchmod_fn = stor_fchmod,
	.chown_fn = stor_chown,
	.fchown_fn = stor_fchown,
	.lchown_fn = stor_lchown,
	.chdir_fn = stor_chdir,
	.getwd_fn = stor_getwd,
	.ntimes_fn = stor_ntimes,
	.ftruncate_fn = stor_ftruncate,
	.fallocate_fn = stor_fallocate,
	.lock_fn = stor_lock,
	.kernel_flock_fn = stor_kernel_flock,
	.linux_setlease_fn = stor_linux_setlease,
	.getlock_fn = stor_getlock,
	.symlink_fn = stor_symlink,
	.readlink_fn = stor_vfs_readlink,
	.link_fn = stor_link,
	.mknod_fn = stor_mknod,
	.realpath_fn = stor_realpath,
	.chflags_fn = stor_chflags,
	.file_id_create_fn = stor_file_id_create,
	.offload_read_send_fn = stor_offload_read_send,
	.offload_read_recv_fn = stor_offload_read_recv,
	.offload_write_send_fn = stor_offload_write_send,
	.offload_write_recv_fn = stor_offload_write_recv,
	.get_compression_fn = stor_get_compression,
	.set_compression_fn = stor_set_compression,

	.streaminfo_fn = stor_streaminfo,
	.get_real_filename_fn = stor_get_real_filename,
	.connectpath_fn = stor_connectpath,
	.brl_lock_windows_fn = stor_brl_lock_windows,
	.brl_unlock_windows_fn = stor_brl_unlock_windows,
	.brl_cancel_windows_fn = stor_brl_cancel_windows,
	.strict_lock_check_fn = stor_strict_lock_check,
	.translate_name_fn = stor_translate_name,
	.fsctl_fn = stor_fsctl,
	.readdir_attr_fn = stor_readdir_attr,

	/* DOS attributes. */
	.get_dos_attributes_fn = stor_get_dos_attributes,
	.fget_dos_attributes_fn = stor_fget_dos_attributes,
	.set_dos_attributes_fn = stor_set_dos_attributes,
	.fset_dos_attributes_fn = stor_fset_dos_attributes,

	/* NT ACL operations. */

	.fget_nt_acl_fn = stor_fget_nt_acl,
	.get_nt_acl_fn = stor_get_nt_acl,
	.fset_nt_acl_fn = stor_fset_nt_acl,

	/* POSIX ACL operations. */

	.chmod_acl_fn = stor_chmod_acl,
	.fchmod_acl_fn = stor_fchmod_acl,

	.sys_acl_get_file_fn = stor_sys_acl_get_file,
	.sys_acl_get_fd_fn = stor_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = stor_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = stor_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = stor_sys_acl_set_file,
	.sys_acl_set_fd_fn = stor_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = stor_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = stor_getxattr,
	.fgetxattr_fn = stor_fgetxattr,
	.listxattr_fn = stor_listxattr,
	.flistxattr_fn = stor_flistxattr,
	.removexattr_fn = stor_removexattr,
	.fremovexattr_fn = stor_fremovexattr,
	.setxattr_fn = stor_setxattr,
	.fsetxattr_fn = stor_fsetxattr,

	/* aio operations */
	.aio_force_fn = stor_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_stor_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "stor",
				&stor_fns);
}
