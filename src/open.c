/*
 * open.c
 *
 * Envelope for the standard 'open' function.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"

#define DE DEB( "open" );


//----------------------------------------------------------------------------
// open()
// ~~~~~~
// Envelope for 'open' function
// Status: almost finished
//----------------------------------------------------------------------------
int
open( const char *path, int flags, ... )
{
  va_list ap;
  mode_t mode = 0;
  int ret, sfs_queue = -1, reply_queue = -1, reply_queue_id, rett;
  struct s_msg msgb;
  char buf[SFS_MAX_PATH];
  long auth;
  uid_t uid;
  struct new_stat st;
  file_location *fl;
_DE
 
  va_start( ap, flags );
  if (flags&O_CREAT)
    mode = va_arg( ap, mode_t );
  
//  sfs_debug( "open", "%s,%d,%d.", path, flags, mode );

  uid = getuid();
 
DE
  if (__syscall_stat( path, &st ) == -1) {
    sfs_debug( "open", "cannot fstat the: %s", path );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "open", "regular file %s", path );
    rett = SFS_REPLY_ENCRYPTED;
  }
  else {
//    sfs_debug( "open", "something strange: %s:%d", path, st.st_mode );
    rett = SFS_REPLY_OK;
  }
    
DE
  if (flags & O_WRONLY) {
//    sfs_debug( "open", "WRONLY" );
    flags &= (~O_WRONLY);
    flags |= O_RDWR;
  }


DE
  ret = __open( path, flags & (~O_APPEND), mode );
  if (ret == -1) {
    sfs_debug( "open", "invalid return status: %d", ret );
    return -1;
  }

DE
  if (rett == SFS_REPLY_OK) {
    sfs_debug( "open", "file could NOT be encrypted" );
    return ret;
  }

DE
  sprintf( buf, "%s/%d", SFS_DIR, uid );
  auth = sfs_auth( buf );
  if (auth == -1) {
    sfs_debug( "open", "authorization error" );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  sfs_queue = msgget( SFS_D_QUEUE_ID, SFS_R_QUEUE_PERM );
  if (sfs_queue == -1) {
    sfs_debug( "open", "cannot get message queue: %d", errno );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }

DE
  if (!sfs_lib_srand) {
    srand( time( 0 ) );
    sfs_lib_srand = 1;
  }
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    sfs_debug( "open", "cannot get reply queue" );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }
  
 /*
  * Connect to daemon and tell him we are openning the file "path"
  * And daemon tell us if something goes wrong.
  * If yes return -1 and set errno to appropriate value.
  *
  */
  
DE
  msgb.mtype = SFS_MESSAGE;
  msgb.sfs_msg.sfs_req_type = SFS_OPEN_REQ;
  msgb.sfs_msg.sfs_req_auth = auth;
  msgb.sfs_msg.sfs_req_uid = uid;
  msgb.sfs_msg.sfs_req.sfs_open.pid = getpid();
  msgb.sfs_msg.sfs_req.sfs_open.uid = uid;
  msgb.sfs_msg.sfs_req.sfs_open.gid = getgid();
  msgb.sfs_msg.sfs_req.sfs_open.fd = ret;
  msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

  fl = sfs_parse_file_path(path);
  if (!fl) {
    sfs_debug( "sfs_add_file_key", "parse error" );
    return -1;
  }

  strncpy( msgb.sfs_msg.sfs_req.sfs_open.dir, fl->dir, SFS_MAX_PATH );
  strncpy( msgb.sfs_msg.sfs_req.sfs_open.name, fl->name, SFS_MAX_PATH );
  
DE
  if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
    sfs_debug( "open", "cannot send message: %d", errno );
    msgctl( reply_queue, IPC_RMID, NULL );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }
  
 /*
  * Wait for reply on reply_queue
  *
  */

DE
  if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
    sfs_debug( "open", "receive message error: %d", errno );
    msgctl( reply_queue, IPC_RMID, NULL );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
    sfs_debug( "open", "receive reply message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
    sfs_debug( "open", "sfsd open error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __close( ret );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  if ( flags & O_APPEND ) {
//    sfs_debug( "open", "APPEND" );
    msgb.mtype = SFS_MESSAGE;
    msgb.sfs_msg.sfs_req_type = SFS_GETSIZE_REQ;
    msgb.sfs_msg.sfs_req_auth = auth;
    msgb.sfs_msg.sfs_req_uid = uid;
    msgb.sfs_msg.sfs_req.sfs_size.pid = getpid();
    msgb.sfs_msg.sfs_req.sfs_size.uid = uid;
    msgb.sfs_msg.sfs_req.sfs_size.fd = ret;
    msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

DE
    if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
      sfs_debug( "open", "cannot send message: %d", errno );
      msgctl( reply_queue, IPC_RMID, NULL );
      __close( ret );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
    if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
      sfs_debug( "open", "receive message error: %d", errno );
      msgctl( reply_queue, IPC_RMID, NULL );
      __close( ret );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
    if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
      sfs_debug( "open", "receive reply message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __close( ret );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
    if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
      sfs_debug( "open", "sfsd open error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __close( ret );
      errno = SFS_ERRNO;
      return -1;
    }

DE
    if (__lseek( ret, msgb.sfs_msg.sfs_req.sfs_size.size, SEEK_SET ) == -1) {
      sfs_debug( "open", "end seek error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __close( ret );
      errno = SFS_ERRNO;
      return -1;
    }
DE
  }
  
DE
  msgctl( reply_queue, IPC_RMID, NULL );
//  sfs_debug( "open", "finished %s,%d,%d.", path, flags, mode );

  return ret;
}

