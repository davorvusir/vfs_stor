# vfs_stor
Samba and iRODS in perfect harmony

The word "stor" in vfs_stor is the swedish word "stör" and is pronounced [stø:r]. The english translation is "rod".

Both Linux and Mac OS have different means of contacting iRODS Zone (http://irods.org/ and http://irods.org/wp-content/uploads/2016/06/technical-overview-2016-web.pdf). Both installable binaries and a GUI (Kanki)

But Windows is having trouble. This is an attempt to close that gap by develop a VFS module that is able to "talk iRODS". Here is some information about VFS modules: https://wiki.samba.org/index.php/Developer_documentation#VFS and https://github.com/samba-team/samba/tree/master/source3/modules.
