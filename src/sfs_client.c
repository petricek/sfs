/*
 * sfs_client.c
 *
 * Client only for testing of SFS daemon
 * 
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */
 
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#include "sfs.h"
#include "sfs_debug.h"

#define perr(args...) { sfs_debug(##args); exit(1); }


//----------------------------------------------------------------------------
// main()
// ~~~~~~
// SFS universal client main() function
//----------------------------------------------------------------------------
int main()
{
 struct s_msg msgb;
 int what;
 int sfs_queue = -1;

 sfs_debug( "sfs_client", "initializing." );
 sfs_queue = msgget(SFS_D_QUEUE_ID,SFS_R_QUEUE_PERM);
 if(sfs_queue == -1)
   perr( "sfs_client", "cannot get message queue." );
 sfs_debug( "sfs_client", "initialized." );

 msgb.mtype = SFS_MESSAGE;
 sfs_debug( "sfs_client", "entering the main loop." );
 for(;;)
 {
  fprintf(stdout,"Which op? ");
  fscanf(stdin,"%d",&what);
  switch(msgb.sfs_msg.sfs_req_type = what)
  {
   case SFS_STRING_REQ:
    fprintf(stdout,"String: ");
    fscanf(stdin,"%s",msgb.sfs_msg.sfs_req.sfs_string);
    sfs_debug( "sfs_client", "got string: %s.", msgb.sfs_msg.sfs_req.sfs_string );
    break;
   case SFS_LOGIN_REQ:
    fprintf(stdout,"Name pass uid gid: ");
    fscanf(stdin,"%s %s %d %d",msgb.sfs_msg.sfs_req.sfs_login.name,msgb.sfs_msg.sfs_req.sfs_login.key,&(msgb.sfs_msg.sfs_req.sfs_login.uid),&(msgb.sfs_msg.sfs_req.sfs_login.gid));
    break;
   case 0:
    return 0;
   default:
    break;
  }
  sfs_debug( "sfs_client", "sending massage" );
  if(msgsnd(sfs_queue,&msgb,SFS_MSG_SIZE,0) == -1)
   perr( "sfs_client", "cannot send message" );
  sfs_debug( "sfs_client", "message sent" );
 }

 return 0;
}

