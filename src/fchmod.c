/*
 * fchmod.c
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 * An envelope for fchmod function
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"


//----------------------------------------------------------------------------
// fchmod()
// ~~~~~~~~
// Envelope for 'fchmod' function
// Status: almost finished
//----------------------------------------------------------------------------
int
fchmod( int fd, mode_t mode )
{
  uid_t uid;
  int ret, rett;
  struct new_stat st;
 
  uid = getuid();
//  sfs_debug( "fchmod", "process %d called fchmod(%d,%d)", getpid(), fd, mode );
 
  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "close", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "fchmod", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "fchmod", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return -1;
    }
    if (rett == SFS_REPLY_ENCRYPTED) {
      sfs_debug( "fchmod", "cannot fchmod encrypted file" );
      errno = SFS_ERRNO;
      return -1;
    }
  }
//  else
//    sfs_debug( "fchmod", "something strange: %d:%d", fd, st.st_mode );
    
  ret = __fchmod( fd, mode );
   return ret;
}

