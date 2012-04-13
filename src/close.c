/*
 * close.c
 *
 * Envelope for standard 'close' function.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"

#define DE DEB( "close" );


//----------------------------------------------------------------------------
// close()
// ~~~~~~~
// Envelope for 'close' function
// Status: finished
//----------------------------------------------------------------------------
int
close( int fd )
{
  int ret, rett;
  int sfs_queue = -1, reply_queue = -1, reply_queue_id;
  struct s_msg msgb;
  uid_t uid;
  long auth;
  char buf[SFS_MAX_PATH];
  struct new_stat st;
_DE
 
//  sfs_debug( "close", "process %d called close(%d)", getpid(), fd );

  uid = getuid();
 
DE

  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "close", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "close", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "close", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return -1;
    }
  }
  else {
//    sfs_debug( "close", "something strange: %d:%d", fd, st.st_mode );
    rett = SFS_REPLY_OK;
  }
    
DE

  if (rett == SFS_REPLY_OK) {
    ret = __close( fd );
    if (ret == -1) {
      sfs_debug( "close", "invalid return status: %d", ret );
      return -1;
    }
    else {
//      sfs_debug( "close", "file is NOT encrypted" );
      return ret;
    }
  }

//  sfs_debug( "close", "file IS encrypted" );

DE

 /*
  * Connect to daemon and tell him we are openning the file "path"
  * And daemon tell us if something goes wrong.
  * If yes return -1 and set errno to appropriate value.
  *
  */

  sprintf( buf, "%s/%d", SFS_DIR, uid );
  auth = sfs_auth( buf );
  if (auth == -1) {
    sfs_debug( "close", "authorization error" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  msgb.mtype = SFS_MESSAGE;
  msgb.sfs_msg.sfs_req_type = SFS_CLOSE_REQ;
  msgb.sfs_msg.sfs_req_auth = auth;
  msgb.sfs_msg.sfs_req_uid = uid;
  msgb.sfs_msg.sfs_req.sfs_close.fd = fd;
  msgb.sfs_msg.sfs_req.sfs_close.pid = getpid();
  
  sfs_queue = msgget( SFS_D_QUEUE_ID, SFS_R_QUEUE_PERM );
  if (sfs_queue == -1) {
    sfs_debug( "close", "cannot get message queue" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  srand( time( 0 ) );
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    if (errno == EEXIST) {
      reply_queue_id = rand();
      reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
      if (reply_queue == -1) {
        sfs_debug( "close", "%d: cannot get reply queue %d", errno, reply_queue_id );
        errno = SFS_ERRNO;
        return -1;
      }
    }
  }
  
DE

  msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

  if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
    sfs_debug( "close", "cannot send message" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
 /*
  * Wait for reply ???
  *
  */

DE

  if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
    sfs_debug( "close", "receive message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
    sfs_debug( "close", "receive reply message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
    sfs_debug( "close", "sfsd login error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  msgctl( reply_queue, IPC_RMID, NULL );
//  sfs_debug( "close", "finished: process %d called close(%d)", getpid(), fd );
    
  return ret;
}

