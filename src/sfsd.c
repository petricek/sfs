/*
 * sfsd.c
 *
 * The main SFS daemon functions
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */
 
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>

#define _SFS_DEBUG_DAEMON

#include "sfsd.h"
#include "sfs_lib.h"
#include "sfs_misc.h"
#include "sfs_debug.h"
#include "sfs_secure.h"


/*
 * SFS daemon global variables
 *
 */

//----------------------------------------------------------------------------
// sfsd_queue
// ~~~~~~~~~~
// The main SFS daemon message queue
//----------------------------------------------------------------------------
int sfsd_queue = -1;

//----------------------------------------------------------------------------
// sfsd_daemon
// ~~~~~~~~~~~
// Start SFS daemon as daemon or not
//----------------------------------------------------------------------------
int sfsd_daemon = 1;


/*
 * SFS daemon functions
 *
 */

//----------------------------------------------------------------------------
// sfsd_init()
// ~~~~~~~~~~~
// Initializes SFS daemon
// Status: finished
//----------------------------------------------------------------------------
int
sfsd_init( void )
{
  sfs_debug( "sfsd_init", "initializing sfsd." );
  signal( SIGHUP, (void(*)(int))sfsd_restart );  
  signal( SIGTERM, sfsd_signal );  
  signal( SIGINT, sfsd_signal );  
  signal( SIGQUIT, sfsd_signal );  
  sfsd_queue = msgget( SFS_D_QUEUE_ID, SFS_D_QUEUE_PERM|IPC_CREAT|IPC_EXCL );
  if (sfsd_queue == -1) {
    sfs_debug( "sfsd_init", "cannot get message queue." );
    return 1;
  }
  sfs_debug( "sfsd_init", "MSG_MAX: %d MSG_SIZE: %d", SFS_MSG_MAX, SFS_MSG_SIZE );
  if (sfs_init_requests() != SFS_REPLY_OK) {
    sfs_debug( "sfsd_init", "initializing requests error." );
    return 1;
  }
  sfs_debug( "sfsd_init", "initialized." );
  return 0;
}


//----------------------------------------------------------------------------
// sfsd_destroy()
// ~~~~~~~~~~~~~~
// Destroys SFS daemon
// Status: finished
//----------------------------------------------------------------------------
int
sfsd_destroy( void )
{
  sfs_debug( "sfsd_destroy", "destroying." );
  if (sfsd_queue != -1)
    if (msgctl( sfsd_queue, IPC_RMID, NULL ) == -1) {
      sfs_debug( "sfsd_destroy", "message queue cannot be destroyed." );
      return 1;
    }
  sfs_debug( "sfsd_destroy", "destroyed." );
  return 0;
}


//----------------------------------------------------------------------------
// sfsd_restart()
// ~~~~~~~~~~~~~~
// Status: finished
// Restarts SFS daemon
//----------------------------------------------------------------------------
void
sfsd_restart( void )
{
  sfs_debug( "sfsd_restart", "restarting." );
  sfs_debug( "sfsd_restart", "restarted." );
}


//----------------------------------------------------------------------------
// sfsd_signal()
// ~~~~~~~~~~~~~
// Handles signals to SFS daemon
// Status: finished
//----------------------------------------------------------------------------
void
sfsd_signal( int signum )
{
  sfsd_destroy();
  sfs_debug( "sfsd_signal", "exitting on signal %d", signum );
  exit( 0 );
}


#undef DE
#define DE //DEB( "sfsd_main" );
#undef _DE
#define _DE

//----------------------------------------------------------------------------
// sfsd_main()
// ~~~~~~~~~~~
// SFS daemon main loop
// Status: finished
//----------------------------------------------------------------------------
int
sfsd_main( void )
{
  struct s_msg msgb;
  char path[SFS_MAX_PATH];
  long auth; //, debug = 0;
  int reply_queue = -1, reply_queue_id, ret;
_DE

//  sfs_debug( "sfsd_main", "entering the main loop." );
  for (;;) {
    if (msgrcv( sfsd_queue, &msgb, SFS_MSG_SIZE, SFS_MESSAGE, 0 ) == -1) {
      sfs_debug( "sfsd_main", "message queue receive error." );
      return 1;
    }

DE

    reply_queue_id = msgb.sfs_msg.sfs_req_reply_queue;
    reply_queue = msgget( reply_queue_id, SFS_C_QUEUE_PERM );
    if (reply_queue == -1) {
      sfs_debug( "sfsd_main", "cannot get message queue." );
      continue;
    }
    
DE

    if (msgb.sfs_msg.sfs_req_type == SFS_LOGIN_REQ)
      auth = sfs_auth( SFS_LOGIN_FILE );
    else {
      sprintf( path, "%s/%d", SFS_DIR, msgb.sfs_msg.sfs_req_uid );
      auth = sfs_auth( path );
    }
    
DE

    if (auth == -1) {
      sfs_debug( "sfsd_main", "authorization error" );
      msgb.sfs_msg.sfs_req_auth = SFS_REPLY_FAIL;
      if (msgsnd( reply_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1)
        sfs_debug( "sfsd_main", "cannot send error reply." );
      continue;
    }
    
DE

    if (auth != msgb.sfs_msg.sfs_req_auth) {
      sfs_debug( "sfsd_main", "authorization error" );
      msgb.sfs_msg.sfs_req_auth = SFS_REPLY_FAIL;
      if (msgsnd( reply_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1)
        sfs_debug( "sfsd_main", "cannot send error reply." );
      continue;
    }
    
DE

    switch (msgb.sfs_msg.sfs_req_type) {
      case SFS_IS_REQ:
        ret = sfs_is_request( &(msgb.sfs_msg.sfs_req.sfs_is) );
        break;
      case SFS_STRING_REQ:
        ret = sfs_string_request( msgb.sfs_msg.sfs_req.sfs_string );
        break;
      case SFS_OPEN_REQ:
        ret = sfs_open_request( &(msgb.sfs_msg.sfs_req.sfs_open) );
        break;
      case SFS_CLOSE_REQ:
        ret = sfs_close_request( &(msgb.sfs_msg.sfs_req.sfs_close) );
        break;
      case SFS_READ_REQ:
        ret = sfs_read_request( &(msgb.sfs_msg.sfs_req.sfs_read) );
        break;
      case SFS_WRITE_REQ:
        ret = sfs_write_request( &(msgb.sfs_msg.sfs_req.sfs_write) );
        break;
      case SFS_CHMOD_REQ:
        ret = sfs_chmod_request( &(msgb.sfs_msg.sfs_req.sfs_chmod) );
        break;
      case SFS_FCHMOD_REQ:
        ret = sfs_fchmod_request( &(msgb.sfs_msg.sfs_req.sfs_fchmod) );
        break;
      case SFS_LOGIN_REQ:
        ret = sfs_login_request( &(msgb.sfs_msg.sfs_req.sfs_login) );
        break;
      case SFS_CHPASS_REQ:
        ret = sfs_chpass_request( &(msgb.sfs_msg.sfs_req.sfs_chpass) );
        break;
      case SFS_DUMP_REQ:
        ret = sfs_dump_request();
        break;
      case SFS_GETSIZE_REQ:
        ret = sfs_getsize_request( &(msgb.sfs_msg.sfs_req.sfs_size));
        break;
      case SFS_SETSIZE_REQ:
        ret = sfs_setsize_request( &(msgb.sfs_msg.sfs_req.sfs_size));
        break;
      default:
        sfs_debug( "sfsd_main", "are you making jokes? (unknown type: %ld)", 
               msgb.sfs_msg.sfs_req_type );
        continue;
    }

DE

    /*
     * Return O.K. or Fail Reply
     *
     */

    msgb.sfs_msg.sfs_req_type = SFS_REPLY_REQ;

    if (ret == SFS_REPLY_OK)
      msgb.sfs_msg.sfs_req_auth = SFS_REPLY_OK;
    else
      msgb.sfs_msg.sfs_req_auth = ret; /* SFS_REPLY_FAIL; */
      
DE

    if (msgsnd( reply_queue, &msgb, SFS_MSG_SIZE, 0 ) == -1) {
      sfs_debug( "sfsd_main", "cannot send reply." );
      continue;
    }
    
  }
}


//----------------------------------------------------------------------------
// sfsd_daemon_setup()
// ~~~~~~~~~~~~~~~~~~~
// Starts SFS daemon as daemon
// Status: finished
//----------------------------------------------------------------------------
int
sfsd_daemon_setup(void)
{
  pid_t pid;
  
  close( 0 );
  close( 1 );
  close( 2 );

  if ((open( "/dev/null", O_RDWR ) != 0) ||
      (open( "/dev/null", O_RDWR ) != 1) ||
      (open( "/dev/null", O_RDWR ) != 2)) {
    sfs_debug( "sfsd_setup", "Error redirecting I/O" );
    return 1;
  }
                                                                             
  pid = fork();
  if (pid == -1) {
    sfs_debug( "sfsd_setup", "cannot fork." );
    return 1;
  }
  else
    if (pid != 0) exit( 0 );

  return 0;
}


#undef DE
#define DE //DEB( "sfsd" );

//----------------------------------------------------------------------------
// main()
// ~~~~~~
// SFS daemon main() function
// Status: finished
//----------------------------------------------------------------------------
int
main()
{
_DE
DE
  if (sfsd_daemon)
    if (sfsd_daemon_setup())
      return 1;
DE
  if (sfsd_init())
    return 1;
DE
  if (sfsd_main()) {
    sfsd_destroy();
    return 1;
  }

  sfsd_destroy();  /* never reached */
  return 0;
}

