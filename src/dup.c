/*
 * dup.c
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 * Envelopes for dup functions
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
// dup()
// ~~~~~
// Envelope for 'dup' function
// Status: almost finished
//----------------------------------------------------------------------------
int
dup( int fd )
{
  uid_t uid;
  int ret, rett;
  struct new_stat st;
 
  uid = getuid();
//  sfs_debug( "dup", "process %d called dup(%d)", getpid(), fd );
 
  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "close", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "dup", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "dup", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return -1;
    }
    if (rett == SFS_REPLY_ENCRYPTED) {
      sfs_debug( "dup", "cannot dup encrypted file" );
      errno = SFS_ERRNO;
      return -1;
    }
  }
//  else
//    sfs_debug( "dup", "something strange: %d:%d", fd, st.st_mode );
    
  ret = __dup( fd );
   return ret;
}


//----------------------------------------------------------------------------
// dup2()
// ~~~~~
// Envelope for 'dup2' function
// Status: almost finished
//----------------------------------------------------------------------------
int
dup2( int fd, int newfd )
{
  uid_t uid;
  int ret, rett;
  struct new_stat st;
 
  uid = getuid();
//  sfs_debug( "dup2", "process %d called dup2(%d,%d)", getpid(), fd, newfd );
 
  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "close", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "dup2", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "dup2", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return -1;
    }
    if (rett == SFS_REPLY_ENCRYPTED) {
      sfs_debug( "dup2", "cannot dup2 encrypted file" );
      errno = SFS_ERRNO;
      return -1;
    }
  }
//  else
//    sfs_debug( "dup2", "something strange: %d:%d", fd, st.st_mode );
    
  ret = __dup2( fd, newfd );
   return ret;
}

