/*
 * sfs_login.c
 *
 * Log in to the sfs subsystem.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
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
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_misc.h"
#include "sfs_debug.h"
#include "sfs_secure.h"

#undef _DE
#define _DE
#define DE //DEB( "sfs_login" );


//----------------------------------------------------------------------------
// sfs_login()
// ~~~~~~~~~~~
// Login to SFS subsystem
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_login( void )
{
  char *buf=NULL, path[SFS_MAX_PATH];
  char *ekey=NULL, *ekey_bin=NULL, *dkey_bin=NULL, *dkey=NULL;
  struct s_msg msgb;
  int sfs_queue = -1, reply_queue = -1, reply_queue_id, len;
  long auth=0;
_DE

  msgb.mtype = SFS_MESSAGE;
  msgb.sfs_msg.sfs_req_type = SFS_LOGIN_REQ;
  msgb.sfs_msg.sfs_req_uid = getuid();

DE
  auth = sfs_auth( SFS_LOGIN_FILE );
  if (auth == -1) {
    sfs_debug( "sfs_login", "login authorization error." );
    return 1;
  }
  msgb.sfs_msg.sfs_req_auth = auth;

DE
/*
 * buf = getlogin();
 * if (!buf)
 *   sfs_debug( "sfs_login", "login is empty" );
 */
 
  msgb.sfs_msg.sfs_req.sfs_login.uid = getuid();
  msgb.sfs_msg.sfs_req.sfs_login.gid = getgid();

DE
  ekey = sfs_read_user_private_key( getuid() );
  if (!ekey) {
    sfs_debug( "sfs_login", "read user private key error" );
    return 1;
  }
//  sfs_debug( "sfs_login", "user private key:\n%s",ekey );
//  sfs_debug( "sfs_login", "user private key length: %d", strlen( ekey ));

DE
  sfs_queue = msgget( SFS_D_QUEUE_ID, 0622 );
  if (sfs_queue == -1) {
    sfs_debug( "sfs_login", "cannot get message queue %d: %d", errno, SFS_D_QUEUE_ID );
    return 1;
  }

DE
  srand( time( 0 ) );
  reply_queue_id = rand();
  reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (reply_queue == -1) {
    sfs_debug( "sfs_login", "cannot get reply queue: %d", errno );
    return 1;
  }
 
DE
  buf = (char*) malloc( SFS_MAX_USER );
  if (!buf) {
    sfs_debug( "sfs_login", "memory error: %d", errno );
    return 1;
  }

DE  
  printf( SFS_LOGIN_USERNAME );
  if (!fgets( buf, SFS_MAX_USER, stdin )) {
    sfs_debug( "sfs_login", "login is empty" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }

DE
  strncpy( msgb.sfs_msg.sfs_req.sfs_login.name, buf, SFS_MAX_USER );

DE
  if(buf)
  {
    free( buf );
    buf=NULL;
  }
  buf = getpass( SFS_LOGIN_PASSWD );
  if (!buf) {
    sfs_debug( "sfs_login", "cannot get password" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
    
DE
  ekey_bin = hex2bit( ekey, 0 );
  if (!ekey_bin) {
    sfs_debug( "sfs_login", "hex2bit error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
  len = strlen( ekey )/2;
  dkey_bin = sfs_sym_decrypt( buf, ekey_bin, len );
  if (!dkey_bin) {
    sfs_debug( "sfs_login", "sfs_sym_decrypt error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
  dkey = bit2hex( dkey_bin, len );
  if (!dkey ) {
    sfs_debug( "sfs_login", "bit2hex error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
//  sfs_debug( "sfs_login", "decrypted user private key:\n%s", dkey );
  strncpy( msgb.sfs_msg.sfs_req.sfs_login.key, dkey, SFS_MAX_KEY );

  sprintf( path, "%s/%d", SFS_DIR, msgb.sfs_msg.sfs_req.sfs_login.uid );
  auth = sfs_auth( path );
  if (auth == -1) {
    sfs_debug( "sfs_login", "authorization error." );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
//  msgb.sfs_msg.sfs_req.sfs_login.auth = auth;
  msgb.sfs_msg.sfs_req_reply_queue = reply_queue_id;

DE
  if (msgsnd( sfs_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
    sfs_debug( "sfs_login", "cannot send message: %d", errno );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }

/*
 * Wait for reply on reply_queue
 *
 */  

  sfs_debug( "sfs_login", "waiting for reply ..." );
DE
  if (msgrcv( reply_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
    sfs_debug( "sfs_login", "receive message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
  
DE
  if (msgb.sfs_msg.sfs_req_type != SFS_REPLY_REQ) {
    sfs_debug( "sfs_login", "receive reply message error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
  
DE
  if (msgb.sfs_msg.sfs_req_auth != SFS_REPLY_OK) {
    sfs_debug( "sfs_login", "sfsd login error" );
    msgctl( reply_queue, IPC_RMID, NULL );
    return 1;
  }
  
DE
  msgctl( reply_queue, IPC_RMID, NULL );
  return 0;
}


//----------------------------------------------------------------------------
// main()
// ~~~~~~
// SFS login main() function
// Status: finished
//----------------------------------------------------------------------------
int
main()
{
  return !!sfs_login();
}

