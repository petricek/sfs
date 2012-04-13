/*
 * sfs_chmod.c
 *
 * Changing of the 'encrypted' attribute to the particular file
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"

#define DE


//----------------------------------------------------------------------------
// sfs_chmod()
// ~~~~~~~~~~~
// Change the 'encrypted' attribute to some file
// Status: almost finished
//----------------------------------------------------------------------------
int
sfs_chmod( const char *path, int mode )
{
  struct s_msg msgb;
  int sfs_queue = -1, reply_queue = -1, reply_queue_id;
  uid_t uid;
  long auth;
  struct stat st;
  char buf[SFS_MAX_PATH];
  file_location *fl;
 
//  sfs_debug( "sfs_chmod", "process %d called chmod(%s,%d)", getpid(), path, mode );

  if (stat( path, &st ) == -1) {
    sfs_debug( "chmod", "cannot fstat the fd %s", path );
    errno = SFS_ERRNO;
    return -1;
  }
  
  uid = getuid();
  // Not owner or root
  if((st.st_uid != uid) && (uid != 0))
  {
    sfs_debug( "chmod", "not owner : %d:%d", uid, st.st_uid );
    errno = SFS_ERRNO;
    return -1;
  }  

  if (!S_ISREG( st.st_mode )) {
//    sfs_debug( "chmod", "something strange: %s:%d", path, st.st_mode );
    errno = SFS_ERRNO;
    return -1;
  }
  
  // Finds out the authorization key to be sent with decryption requests
  sprintf( buf, "%s/%d", SFS_DIR, uid );
  auth = sfs_auth( buf );
  if (auth == -1) {
    sfs_debug( "chmod", "authorization error" );
    errno = SFS_ERRNO;
    return -1;
  }

  msgb.mtype = SFS_MESSAGE;
  msgb.sfs_msg.sfs_req_type = SFS_CHMOD_REQ;
  msgb.sfs_msg.sfs_req_auth = auth;
  msgb.sfs_msg.sfs_req_uid = uid;
  msgb.sfs_msg.sfs_req.sfs_chmod.uid = st.st_uid;
  msgb.sfs_msg.sfs_req.sfs_chmod.gid = st.st_gid;
  msgb.sfs_msg.sfs_req.sfs_chmod.mode = mode;
  msgb.sfs_msg.sfs_req.sfs_chmod.rights = st.st_mode;
//    sfs_debug( "chmod", "MODE :%d", mode );
  msgb.sfs_msg.sfs_req.sfs_chmod.size = st.st_size;

  fl = sfs_parse_file_path(path);
  if (!fl) {
    sfs_debug( "sfs_chmod", "parse_file_path error" );
    return -1;
  }

  strncpy( msgb.sfs_msg.sfs_req.sfs_chmod.dir, fl->dir, SFS_MAX_PATH );
  strncpy( msgb.sfs_msg.sfs_req.sfs_chmod.name, fl->name, SFS_MAX_PATH );
  
  
  sfs_queue = msgget( SFS_D_QUEUE_ID, SFS_R_QUEUE_PERM );
  if (sfs_queue == -1) {
    sfs_debug( "sfs_chmod", "cannot get message queue" );
    errno = SFS_ERRNO;
    return -1;
  }
  
  srand( time( 0 ) );
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    if (errno == EEXIST) {
      reply_queue_id = rand();
      reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
      if (reply_queue == -1) {
        sfs_debug( "sfs_chmod", "%d: cannot get reply queue %d", errno, reply_queue_id );
        errno = SFS_ERRNO;
        return -1;
      }
    }
  }

  msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

  if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
    sfs_debug( "sfs_chmod", "cannot send message" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
 /*
  * Wait for reply ???
  *
  */

  if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
    sfs_debug( "sfs_chmod", "receive message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
    sfs_debug( "sfs_chmod", "receive reply message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
    sfs_debug( "sfs_chmod", "sfsd reply error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }

  msgctl( reply_queue, IPC_RMID, NULL );
  sfs_debug( "sfs_chmod", "finished: %s", path );
    
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// main()
// ~~~~~~
// SFS chmod main() function
//----------------------------------------------------------------------------
int
main( int argc, char *argv[] )
{
  long mode = -1;
  
  if (argc < 3) {
    sfs_debug( "sfs_chmod", "usage: sfs_chmod <+|-e> <filename>" );
    return 1;
  }
  
  if(strlen(argv[1]) == 2){
    if((argv[1][0] == '+') && (argv[1][1] == 'e'))
      mode = 1;
    if((argv[1][0] == '-') && (argv[1][1] == 'e'))
      mode = 0;
  }
  if(mode == -1)
  {
    sfs_debug( "sfs_chmod", "usage: sfs_chmod <+|-e> <filename>" );
    return 1;
  }

  if (sfs_chmod( argv[2], mode ) == -1) {
    sfs_debug( "sfs_chmod", "cannot change mode: %s, %ld", argv[2], mode );
    return 1;
  }

  sfs_debug( "sfs_chmod", "mode changed: %s,%ld", argv[2], mode );
  return 0;
}

