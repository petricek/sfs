/*
 * mmap.c
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 * An envelope for mmap function
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"


//----------------------------------------------------------------------------
// mmap()
// ~~~~~~
// Envelope for 'mmap' function
// Status: almost finished
//----------------------------------------------------------------------------
char*
mmap( char *start, size_t length, int prot, int flags, int fd, off_t offset )
{
  uid_t uid;
  int rett;
  char *ret;
  struct new_stat st;
 
  uid = getuid();
//  sfs_debug( "mmap", "process %d called mmap(%d)", getpid(), fd );
 
  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "close", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return NULL;
  }
  
  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "mmap", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "mmap", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return NULL;
    }
    if (rett == SFS_REPLY_ENCRYPTED) {
      sfs_debug( "mmap", "cannot mmap encrypted file" );
      errno = SFS_ERRNO;
      return NULL;
    }
  }
//  else
//    sfs_debug( "mmap", "something strange: %d:%d", fd, st.st_mode );
    
  ret = __mmap( start, length, prot, flags, fd, offset );
   return ret;
}

/****************

off_t pos;
char *mem;

///// why? see msync(2) /////

if (prot&PROT_WRITE) {
  sfs_debug( "mmap", "memory mapping error: cannot map for writing" );
  errno = SFS_ERRNO;
  return NULL;
}

mem = (char*) malloc( length );
if (!mem) {
  sfs_debug( "mmap", "memory error: %d", errno );
  errno = SFS_ERRNO;
  return NULL;
}

pos = __lseek( fd, 0, SEEK_CUR );
if (pos == -1) {
  sfs_debug( "mmap", "lseek error: %d", errno );
  errno = SFS_ERRNO;
  free( mem );
  return NULL;
}

if (__lseek( fd, offset, SEEK_SET ) == -1) {
  sfs_debug( "mmap", "lseek error2: %d", errno );
  errno = SFS_ERRNO;
  __lseek( fd, pos, SEEK_SET );
  free( mem );
  return NULL;
}

if (read( fd, mem, length ) < length) {
  sfs_debug( "mmap", "read error: %d", errno );
  errno = SFS_ERRNO;
  __lseek( fd, pos, SEEK_SET );
  free( mem );
  return NULL;
}

__lseek( fd, pos, SEEK_SET );
return mem;

*******************/
