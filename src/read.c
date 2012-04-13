/*
 * read.c
 *
 * Envelope for standard 'read' function.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>,
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_debug.h"

#define DE DEB( "read" );


//--------------------------------------------------------------------------
// read()
// ~~~~~~
// Reads data from file and asks demon to decrypt it
// Status: NOT finished
//--------------------------------------------------------------------------
ssize_t
read( int fd, void *where, size_t count )
{
  ssize_t ret;
  uid_t uid;
  long auth;
  char buf[SFS_MAX_PATH], *read_buf;
  struct s_msg msgb;
  int sfs_queue = -1, reply_queue = -1, reply_queue_id, rett;
  ssize_t i;
  size_t j;
  struct sfs_offset off, *new_off;
  struct new_stat st;
  off_t size;
_DE

//  sfs_debug( "read", "%d", fd );

  uid = getuid();

DE

  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "read", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "read", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "read", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return -1;
    }
  }
  else {
//    sfs_debug( "read", "something strange: %d:%d", fd, st.st_mode );
    rett = SFS_REPLY_OK;
  }
    
DE
    
  if (rett == SFS_REPLY_OK) {
    ret = __read( fd, where, count );
    if (ret == -1) {
      sfs_debug( "read", "invalid return status" );
      return -1;
    }
    else {
//      sfs_debug( "read", "file is NOT encrypted" );
      return ret;
    }
  }

//  sfs_debug( "read", "file IS encrypted" );
 
  off.count = count;  
  off.offset = __lseek( fd, 0, SEEK_CUR );
  if (off.offset == -1) {
    sfs_debug( "read", "cannot get current position" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
    
  // Generates smallest bigger offset containing requested data, that
  // is a multiple of BF_BLOCK_SIZE
  new_off = sfs_generate_aligned_offset( &off );
  if (!new_off) {
    sfs_debug( "read", "cannot generate new offset" );
    errno = SFS_ERRNO;
    return -1;
  }
  
//  sfs_debug( "read", "process %d called read(%d,%p,%d) on pos: %ld", getpid(), fd, buf, off.count, off.offset );
//  sfs_debug( "read", "process %d called __read(%d,%p,%d) on pos: %ld", getpid(), fd, buf, new_off->count, new_off->offset );

  // Seeks to the beginning of new offset
  if (__lseek( fd, new_off->offset, SEEK_SET ) == -1) {
    sfs_debug( "read", "lseek error" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  // Allocates buffer for encrypted and then decrypted data.  
  if (!(read_buf = (char*)malloc( new_off->count ))) {
    sfs_debug( "read", "not enough memory" );
    __lseek( fd, off.offset, SEEK_SET );
    errno = SFS_ERRNO;
    return -1;
  }

DE 

  // Finds out the authorization key to be sent with decryption requests
  sprintf( buf, "%s/%d", SFS_DIR, uid );
  auth = sfs_auth( buf );
  if (auth == -1) {
    sfs_debug( "open", "authorization error" );
    __lseek( fd, off.offset, SEEK_SET );
    free( read_buf );
    errno = SFS_ERRNO;
    return -1;
  }

DE

  // Finds a free reply queue
  if (!sfs_lib_srand) {
    srand( time( 0 ) );
    sfs_lib_srand = 1;
  }
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    sfs_debug( "read", "cannot get reply queue" );
    __lseek( fd, off.offset, SEEK_SET );
    free( read_buf );
    errno = SFS_ERRNO;
    return -1;
  }

  // Connects to the demon queue
  sfs_queue = msgget( SFS_D_QUEUE_ID, SFS_R_QUEUE_PERM );
  if (sfs_queue == -1) {
    sfs_debug( "read", "cannot get message queue" );
    __lseek( fd, off.offset, SEEK_SET );
    free( read_buf );
    errno = SFS_ERRNO;
    return -1;
  }

DE

  // reads in the encrypted data 
  ret = __read( fd, read_buf, new_off->count );
  if (ret == -1) {
    sfs_debug( "read", "invalid return status" );
    __lseek( fd, off.offset, SEEK_SET );
    free( read_buf );
    errno = SFS_ERRNO;
    return -1;
  }
//  sfs_debug( "read", "ret: %d", ret );

/* Send (read_buf,pid,fd) in a cycle to daemon to decrypt.
 * Receive blocks of decrypted data and assemble it in read_buf.
 */

  
  for (i=0;i<ret;i+=BF_BLOCK_SIZE) {

//    sfs_debug( "read", "i: %d", i );

    // sends 8bytes to demon for decryption 

    // Create message to be sent to demon
    msgb.mtype = SFS_MESSAGE;
    msgb.sfs_msg.sfs_req_type = SFS_READ_REQ;
    msgb.sfs_msg.sfs_req_auth = auth;
    msgb.sfs_msg.sfs_req_uid = uid;
    msgb.sfs_msg.sfs_req.sfs_read.fd = fd;
    msgb.sfs_msg.sfs_req.sfs_read.pid = getpid();
    msgb.sfs_msg.sfs_req.sfs_read.count = BF_BLOCK_SIZE; //new_off->count; ???

    msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;
    
DE
    for (j=0;j<BF_BLOCK_SIZE;j++) {
      msgb.sfs_msg.sfs_req.sfs_read.buf[j] = read_buf[i+j];
//      sfs_debug( "read", "read_buf[%d+%d]: %c", i, j, read_buf[i+j] );
    }

DE
    // Send request
    if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
      sfs_debug( "read", "cannot send message" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }
  
DE
    // receive reply  
    if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
      sfs_debug( "read", "receive message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }
  
DE
    // Error in reply - not a reply?
    if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
      sfs_debug( "read", "receive reply message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }
  
DE
    // Login error - not OK
    if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
      sfs_debug( "read", "sfsd login error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
    for (j=0;j<BF_BLOCK_SIZE;j++) { 
      read_buf[i+j] = msgb.sfs_msg.sfs_req.sfs_read.buf[j];
//      sfs_debug( "read", "read_buf[%d+%d]: %c", i, j, read_buf[i+j] );
    }

  } // main for //

DE
  
  // If the end of file then it is necessary to adjust the actual length of 
  // data
  if(ret < (ssize_t)new_off->count) {
    
    // Create message to be sent to demon
    msgb.mtype = SFS_MESSAGE;
    msgb.sfs_msg.sfs_req_type = SFS_GETSIZE_REQ;
    msgb.sfs_msg.sfs_req_auth = auth;
    msgb.sfs_msg.sfs_req_uid = uid;
    msgb.sfs_msg.sfs_req.sfs_size.fd = fd;
    msgb.sfs_msg.sfs_req.sfs_size.pid = getpid();
    msgb.sfs_msg.sfs_req.sfs_size.uid = uid;

    msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;
    
    // Send request
    if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
      sfs_debug( "read", "cannot send message" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }

    // receive reply  
    if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
      sfs_debug( "read", "receive message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }
  
    // Error in reply - not a reply?
    if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
      sfs_debug( "read", "receive reply message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( read_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    size = msgb.sfs_msg.sfs_req.sfs_size.size;
  }
  else
    size = ret+new_off->offset;
    
DE
 
  // Cuts out the relevant part o decrypted data 
  for(j=0;j<off.count; j++)
    ((char *)where)[j] = read_buf[j+(off.offset % 8)];
  
DE
    
  if (__lseek( fd, off.offset+off.count, SEEK_SET ) == -1) {
    sfs_debug( "read", "back lseek error" );
    __lseek( fd, off.offset, SEEK_SET );
    free( read_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
    
  free( read_buf );
  msgctl( reply_queue, IPC_RMID, NULL );
//  sfs_debug( "read", "finished: %d, %d, %d. %d", fd, ret, count, size );
//  sfs_debug( "read", "returning: %d", ((new_off->offset+ret)>size)?(size-off.offset):count );

  if (!ret) return 0;
  return ((new_off->offset+ret)>size)?(size-off.offset):count;
}

