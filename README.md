# vfs_stor
Samba and iRODS in perfect harmony

The word "stor" in vfs_stor is the swedish word "stör" and is pronounced [stø:r]. The english translation is "rod".

With the all increasing unstructred data, there is an increasing need for storage and and ways to handle it. Whether you work in an SMB or one of the giants, there comes a time when it becomes cumbersome to handle; it grows complex, migration to new storage, backup-copies for resiliance, transfer of ownership when employees leave, sync-n-share, regulatory policies, archiving etc etc. You know all this.

There is an open sourced middleware around, and has been for many years, that makes it possible for you to implement your data management policies. It doesn't matter whether you are responisble for million of files or files that are millions of kilobyte. With a plugin-based architecture you can extend its functionality to fit your needs. With iRODS[1] you can federate and, of course, still apply apply security templates that complies with your organizations policies. The technical overview[2] will get you more up-to-date with iRODS possibilities.

Have a look at the news section to see which prestigious organizations have joined the iRODS consortium[3].

iRODS has got client software, the iCommands, which enables workstations to utilize the powerful middleware. The iCommands are command line utilities for Linux and MacOS. For those who prefer a GUI interface there is Kanki[4,5]. Something is missing, isn't there? What about Windows?

Samba[6] is another powerful open source project that is the software suite used to present file share resources on Linux to Windows clients. Of course it's possible for both Linux and MacOS clients to connect to a file share presented by Samba.

What is the connection between iRODS and Samba? None. Yet. Samba allows to extend its file sharing functionality with Virtual File System (VFS) modules[7,8,9]. In [7] Samba Team outlines some examples of extending Samba and I would like to present to you the Samba VFS module, 'vfs_stor', to use with an iRODS zone. On my Github page I present the VFS module, the project goal, possible drawbacks and a use case besides the obvious file sharing.

As I am no C programmer, I reach out to you; a C programmer with some time on your hands.

Project goal
To develop a Samba VFS module that uses an iRODS zone as storage backend. The VFS module will present the iRODS zone as a SMB file share.

Both Samba and iRODS are Kerberos and LDAP aware which make it possible to make both the Samba server and the iRODS server member of an Active Directory.

Drawbacks/limitations
iRODS doesn't use versioning (to my knowledge) which makes 'Previous versions' not accessible.

As iCommands are going to be used by the Linux server when talking to the iRODS zone, it is a high probability that a file requested from a Windows client, has to be downloaded to the Linux/Samba server first. If that is true, the same is true for uploading files.

Example of use case except the obvious file sharing
Today it is almost mandatory to have a sync-n-share solution in place. ownCloud[10] is one of several suites that offers this functionality. Synchronization clients are available for Linux, MacOS and Windows, Android, iOS and Windows Phone[11].

ownCloud has got several storage connectors. One is the SMB storage connector, which, of course, allows you to connect to standard Windows File Share. This VFS module, vfs_stor, Samba using an iRODS zone with ownCloud on top is an obvious choice. One idea on how to solve this 'ménage à trois' is presented at the 'CS3 Workshop on Cloud Services for File Synchronisation and Sharing'[12] workshop.

If you are a C programmer with some time on your hands, you are most welcome!


[1] https://irods.org
[2] https://irods.org/uploads/2016/06/technical-overview-2016-web.pdf
[3] https://irods.org/news/
[4] https://irods.org/2015/12/update-irods-client-interfaces/
[5] https://github.com/ilarik/kanki-irodsclient
[6] https://www.samba.org/
[7] https://wiki.samba.org/index.php/Writing_a_Samba_VFS_Module
[8] https://github.com/samba-team/samba/tree/master/examples/VFS
[9] https://github.com/samba-team/samba/tree/master/source3/modules
[10] https://www.owncloud.org, https://www.owncloud.com/
[11] https://github.com/owncloud/windows-phone
[12] https://indico.cern.ch/event/565381/contributions/2402652/
