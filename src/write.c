/*
 * write.c
 *
 * Envelope for 'write' function
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#include <errno.h>
#include <stdarg.h>
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

#define DE DEB( "write" );


//----------------------------------------------------------------------------
// write()
// ~~~~~~~
// Asks demon to encrypt the data and writes it to the disk
// Status: NOT finished
//----------------------------------------------------------------------------
ssize_t
write( int fd, const void *what, size_t count )
{
  ssize_t ret;
  uid_t uid;
  long auth;
  char buf[SFS_MAX_PATH], *write_buf;
  struct s_msg msgb;
  int sfs_queue = -1, reply_queue = -1, reply_queue_id, rett;
  size_t i, j;
  struct sfs_offset off, *new_off;
  struct new_stat st;
  off_t size;
_DE

// sfs_debug( "write", "process %d called write(%d,%p,%d)", getpid(), fd, buf, count );

  uid = getuid();

DE

  if (__syscall_fstat( fd, &st ) == -1) {
    sfs_debug( "write", "cannot fstat the fd %d", fd );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE

  if (S_ISREG( st.st_mode )) {
//    sfs_debug( "write", "regular file %d", fd );
    rett = sfs_is_encrypted( fd, uid, getpid() );
    if (rett == -1) {
      sfs_debug( "write", "cannot get state of the file" );
      errno = SFS_ERRNO;
      return -1;
    }
  }
  else {
//    sfs_debug( "write", "something strange: %d:%d", fd, st.st_mode );
    rett = SFS_REPLY_OK;
  }
    
DE
    
  if (rett == SFS_REPLY_OK) {
    ret = __write( fd, what, count );
    if (ret == -1) {
      sfs_debug( "write", "invalid return status" );
      return -1;
    }
    else {
//      sfs_debug( "write", "file is NOT encrypted" );
      return ret;
    }
  }

//  sfs_debug( "write", "file IS encrypted" );
  
  // off represents offset and caunt passed by user
  off.count = count;  
  off.offset = __lseek( fd, 0, SEEK_CUR );
  if (off.offset == -1) {
    sfs_debug( "write", "cannot get current position" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  // Calculates smallest bigger buffer with size a multiple of BF_BLOCK_SIZE  
  new_off = sfs_generate_aligned_offset( &off );
  if (!new_off) {
    sfs_debug( "write", "cannot generate new offset" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  // Creates a bigger buffer containing data to be writen  
  if (!(write_buf = (char*)malloc( new_off->count ))) {
    sfs_debug( "write", "not enough memory" );
    __lseek( fd, off.offset, SEEK_SET );
    errno = SFS_ERRNO;
    return -1;
  }

//  sfs_debug( "write", "process %d called write(%d,%p,%d) on pos: %ld", getpid(), fd, buf, off.count, off.offset );
//  sfs_debug( "write", "process %d called __write(%d,%p,%d) on pos: %ld", getpid(), fd, buf, new_off->count, new_off->offset );

  // Sets position to begining of bigger buffer
  if (__lseek( fd, new_off->offset, SEEK_SET ) == -1) {
    sfs_debug( "write", "lseek error" );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  // Connects to demon queue
  sfs_queue = msgget( SFS_D_QUEUE_ID, SFS_R_QUEUE_PERM );
  if (sfs_queue == -1) {
    sfs_debug( "write", "cannot get message queue" );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }

DE
  // Find autorization key to be sent to the server
  sprintf( buf, "%s/%d", SFS_DIR, uid );
  auth = sfs_auth( buf );
  if (auth == -1) {
    sfs_debug( "write", "authorization error" );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  // Get number of free reply queue    
  srand( time( 0 ) );
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    sfs_debug( "write", "cannot get reply queue" );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  // Reads original data into  bigger buffer
  ret = read(fd, write_buf, new_off->count);  
  
  // Demon decrypts the data !!


  // Combines old data with data that has to be written
  for (i=0;i<off.count;i++) {
    write_buf[(off.offset - new_off->offset) + i] = ((char*)what)[i];
  }
  
  if (ret == -1) {
    sfs_debug( "write", "invalid return status in read of old data" );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
 
DE
  // Sets the position in file to the place where write_buf should be written 
  if (__lseek( fd, new_off->offset, SEEK_SET ) == -1) {
    sfs_debug( "write", "back lseek error" );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
 
/* Send in a cycle (write_buf,pid,fd) to daemon to decrypt.
 * Receive encrypted (write_buf).
 */

 /*
  * Connect to daemon and tell him we are writing to the fd
  * And daemon tell us if something goes wrong.
  * If yes return -1 and set errno to appropriate value.
  *
  */

  
DE
  // cycle in which data is encrypted and assembled in write_buff  
  for (i=0;i<new_off->count;i+=SFS_BF_BLOCK_SIZE) {
    msgb.mtype = SFS_MESSAGE;
    msgb.sfs_msg.sfs_req_type = SFS_WRITE_REQ;
    msgb.sfs_msg.sfs_req_auth = auth;
    msgb.sfs_msg.sfs_req_uid = uid;
    msgb.sfs_msg.sfs_req.sfs_write.fd = fd;
    msgb.sfs_msg.sfs_req.sfs_write.count = SFS_BF_BLOCK_SIZE; //count;
    msgb.sfs_msg.sfs_req.sfs_write.pid = getpid();

    // fill in data to be encrypted by demon
    for (j=0;j<SFS_BF_BLOCK_SIZE;j++) {
      msgb.sfs_msg.sfs_req.sfs_write.buf[j] = write_buf[i+j];
//      sfs_debug( "write", "write_buf[%d,%d]: %c", i, j, write_buf[i+j] );
    }

DE
//    sfs_debug( "write", "count: %d", msgb.sfs_msg.sfs_req.sfs_write.count );

DE
//  for (i=0;i<off.count;i++) {
//    msgb.sfs_msg.sfs_req.sfs_write.buf[i+off.offset-new_off->offset] = ((char*)what)[i];
//    sfs_debug( "write", "write_buf[%d]: %c", i, ((char*)what)[i] );
//  }

DE
//    sfs_debug( "write", "count: %d", msgb.sfs_msg.sfs_req.sfs_write.count );

DE
    msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

    // Sends data for encryption
    if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
      sfs_debug( "write", "cannot send message" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
    
    if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
      sfs_debug( "write", "receive message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
    
    if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
      sfs_debug( "write", "receive reply message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
      
    if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
      sfs_debug( "write", "sfsd login error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE
      
//    for (i=0;i<new_off->count;i++) {
//      write_buf[i] = msgb.sfs_msg.sfs_req.sfs_write.buf[i];
//      sfs_debug( "write", "write_buf[%d]: %c", i, write_buf[i] );
//    }

    for (j=0;j<BF_BLOCK_SIZE;j++) {
      write_buf[i+j] = msgb.sfs_msg.sfs_req.sfs_write.buf[j];
//      sfs_debug( "write", "write_buf[%d+%d]: %c", i, j, write_buf[i+j] );
    }

  } // main for //
      
DE
  ret = __write( fd, write_buf, new_off->count );
  if (ret == -1) {
    sfs_debug( "write", "invalid return status" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    return -1;
  }

DE  
  if (ret < (ssize_t)new_off->count) {
    sfs_debug( "write", "invalid return status" ); /*
    msgctl( reply_queue, IPC_RMID, NULL );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    return -1; */
  }

// Set the right size for the file

  msgb.sfs_msg.sfs_req_auth = auth;
  msgb.sfs_msg.sfs_req_type = SFS_GETSIZE_REQ;
  msgb.sfs_msg.sfs_req.sfs_size.fd = fd;
  msgb.sfs_msg.sfs_req.sfs_size.uid = uid;
  msgb.sfs_msg.sfs_req.sfs_size.pid = getpid();

DE
  if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
    sfs_debug( "write", "cannot send message" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE  
  if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
    sfs_debug( "write", "receive message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE  
  if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
    sfs_debug( "write", "receive reply message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE    
  if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
    sfs_debug( "write", "sfsd login error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
  
DE
  if ((size = __lseek( fd, off.offset+off.count, SEEK_SET )) == -1) {
    sfs_debug( "write", "getting size rror" );
    __lseek( fd, off.offset, SEEK_SET );
    free( write_buf );
    errno = SFS_ERRNO;
    return -1;
  }
 
DE
  if (size > msgb.sfs_msg.sfs_req.sfs_size.size ) {
    msgb.sfs_msg.sfs_req_auth = auth;
    msgb.sfs_msg.sfs_req_type = SFS_SETSIZE_REQ;
    msgb.sfs_msg.sfs_req.sfs_size.fd = fd;
    msgb.sfs_msg.sfs_req.sfs_size.uid = uid;
    msgb.sfs_msg.sfs_req.sfs_size.pid = getpid();
    msgb.sfs_msg.sfs_req.sfs_size.size = size;

DE
    if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
      sfs_debug( "write", "cannot send message" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE  
    if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
      sfs_debug( "write", "receive message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE  
    if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
      sfs_debug( "write", "receive reply message error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
DE    
    if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
      sfs_debug( "write", "sfsd login error" );
      msgctl( reply_queue, IPC_RMID, NULL );
      __lseek( fd, off.offset, SEEK_SET );
      free( write_buf );
      errno = SFS_ERRNO;
      return -1;
    }
    
  }

// Finish him!

DE  
  __lseek( fd, off.count+off.offset, SEEK_SET );

DE
  free( write_buf );

DE
  msgctl( reply_queue, IPC_RMID, NULL );
//  sfs_debug( "write", "finished: %d", fd );

DE
  return off.count;
}

