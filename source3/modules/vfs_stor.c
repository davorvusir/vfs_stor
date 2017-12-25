/* 
 * vfs_stor.c
 * Copyright (C) Davor Vusir, 2017
 *
 * Skeleton VFS module.  Implements dummy versions of all VFS
 * functions.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) Jeremy Allison 2009
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

#include "../source3/include/includes.h"
#include "lib/util/tevent_ntstatus.h"

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * you must re-implement every function.
 */

static int stor_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
	errno = ENOSYS;
	return -1;
}

static void stor_disconnect(vfs_handle_struct *handle)
{
	;
}

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
	errno = ENOSYS;
	return -1;
}

static struct smb_filename *stor_getwd(vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
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
	errno = ENOSYS;
	return NULL;
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