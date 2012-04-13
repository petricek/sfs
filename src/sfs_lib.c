/*
 * sfs_lib.c
 *
 * Miscellaneous library functions.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
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
#include <sys/stat.h>
#include <sys/types.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"

int sfs_lib_srand = 0;

//****************************************************************************
// sfs_is_encrypted()
// ~~~~~~~~~~~~~~~~~~
// Ask sfs daemon if the file is encrypted or not
// Status: finished
//****************************************************************************
int
sfs_is_encrypted( int fd, uid_t uid, pid_t pid )
{
  int sfs_queue = -1, reply_queue = -1, reply_queue_id;
  struct s_msg msgb;
  long auth;
  char buf[SFS_MAX_PATH];
 
  sprintf( buf, "%s/%d", SFS_DIR, uid );
  auth = sfs_auth( buf );
  if (auth == -1) {
    sfs_debug( "sfs_is_encrypted", "authorization error" );
    errno = SFS_ERRNO;
    return -1;
  }
  
  msgb.mtype = SFS_MESSAGE;
  msgb.sfs_msg.sfs_req_type = SFS_IS_REQ;
  msgb.sfs_msg.sfs_req_auth = auth;
  msgb.sfs_msg.sfs_req_uid = uid;
  msgb.sfs_msg.sfs_req.sfs_is.pid = pid;
  msgb.sfs_msg.sfs_req.sfs_is.fd = fd;
  
  sfs_queue = msgget( SFS_D_QUEUE_ID, SFS_R_QUEUE_PERM );
  if (sfs_queue == -1) {
    sfs_debug( "sfs_is_encrypted", "cannot get message queue" );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (!sfs_lib_srand) {
    srand( time( 0 ) );
    sfs_lib_srand = 1;
  }
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    sfs_debug( "sfs_is_encrypted", "cannot get reply queue %d", reply_queue_id );
    errno = SFS_ERRNO;
    return -1;
  }
  
  msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

  if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
    sfs_debug( "sfs_is_encrypted", "cannot send message" );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
 /*
  * Wait for reply ???
  *
  */

  if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
    sfs_debug( "sfs_is_encrypted", "receive message error." );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
    sfs_debug( "sfs_is_encrypted", "receive reply message error." );
    msgctl( reply_queue, IPC_RMID, NULL );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (msgb.sfs_msg.sfs_req_auth == SFS_REPLY_OK) {
    msgctl( reply_queue, IPC_RMID, NULL );
//    sfs_debug( "sfs_is_encrypted", "file %d is NOT encrypted.", fd );
    msgctl( reply_queue, IPC_RMID, NULL );
    return SFS_REPLY_OK;
  }
  if (msgb.sfs_msg.sfs_req_auth == SFS_REPLY_ENCRYPTED) {
    msgctl( reply_queue, IPC_RMID, NULL );
//    sfs_debug( "sfs_is_encrypted", "file %d IS encrypted.", fd );
    msgctl( reply_queue, IPC_RMID, NULL );
    return SFS_REPLY_ENCRYPTED;
  }

  msgctl( reply_queue, IPC_RMID, NULL );
  sfs_debug( "sfs_is_encrypted", "reply error %d.", msgb.sfs_msg.sfs_req_auth );
  return -1;
}

 
//****************************************************************************
// sfs_auth()
// ~~~~~~~~~~
// Return authorization constant from the file path
// Status: finished
//****************************************************************************
long
sfs_auth( const char *path )
{
  int fd;
  long auth;
  char buf[SFS_AUTH_KEY_SIZE+2]; //, *buf2=NULL;
  
  fd = __open( path, O_RDONLY );
  if (fd == -1) {
    sfs_debug( "sfs_auth", "cannot open %s", path );
    errno = SFS_ERRNO;
    return -1;
  }
  
  if (__read( fd, buf, SFS_AUTH_KEY_SIZE ) < SFS_AUTH_KEY_SIZE) {
    sfs_debug( "sfs_auth", "cannot read random key" );
    __close( fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
  buf[SFS_AUTH_KEY_SIZE+1] = 0;
  auth = *((long*)buf);
  
  __close( fd );
  return auth;
}


//****************************************************************************
// sfs_parse_file_path()
// ~~~~~~~~~~~~~~~~~
// Parses path into dir and name using getcwd if necessary 
// Status: finished
//****************************************************************************
file_location*
sfs_parse_file_path( const char * path )
{
  char *end, *dir;
  file_location * fl;

  fl = (file_location*) malloc( sizeof( file_location ) );
  if (!fl) {
    sfs_debug( "sfs_parse_file_path", "mem error" );
    return NULL;
  }

    dir = strdup( path );
  // relative path ==> prepends current directory
  if (dir[0] != '/') {
    char *curdir = (char *) malloc( SFS_MAX_PATH );
    if (!curdir) {
      sfs_debug( "sfs_parse_file_path", "mem error" );
      free( fl );
      return NULL;
    }
    getcwd( curdir, SFS_MAX_PATH );
    strcat( curdir, "/" );
    strcat( curdir, dir);
    free( dir );
    dir = curdir;
  }
  // extracts directory from path
    end = dir + strlen( dir );
    // Skips the filename
    while ((end != dir) && (*end != '/'))
      end--;

  if (*end == '/')
    fl->name = strdup( end+1 );
  *(end+1)=0;

  fl->dir = strdup(dir);
    
  return fl;
}


//****************************************************************************
// sfs_generate_aligned_offset()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Enlarges the region of a file to contain just complete 8byte blocks
// Status: finished
//****************************************************************************
struct sfs_offset*
sfs_generate_aligned_offset( struct sfs_offset *off )
{
  struct sfs_offset *new_off;
  
  new_off = (struct sfs_offset*) malloc( sizeof( struct sfs_offset ) );
  if (!new_off) {
    sfs_debug( "sfs_generate_offset", "mem error" );
    return NULL;
  }
  
  // Rounds offset to nearest lower multiple of 8
  new_off->offset = off->offset - (off->offset % BF_BLOCK_SIZE);  
  // Adjusts the count to nearest higher multiple of 8
  new_off->count = (off->offset % BF_BLOCK_SIZE) + off->count;
  new_off->count = new_off->count - (new_off->count % BF_BLOCK_SIZE) + 8;
  
//  sfs_debug( "sfs_generate_offset", "%d, %d, %d, %d", off->offset, 
//             off->count, new_off->offset, new_off->count );
  
  return new_off;
}

