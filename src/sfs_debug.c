/*
 * sfs_debug.c
 *
 * Debugging and info functions.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */
 
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>

#include "sfs_debug.h"


//----------------------------------------------------------------------------
// show_debug
// ~~~~~~~~~~
// Show debugging outputs?
//----------------------------------------------------------------------------
int show_debug = 1;


//----------------------------------------------------------------------------
// sfs_deb()
// ~~~~~~~~~
// Debugging outputs
// Status: finished
//----------------------------------------------------------------------------
void
sfs_deb( int is_daemon, const char *module_name, const char *fmt,... )
{
 char buf[SFS_DEBUG_MAX_BUF];
 va_list args;

 if (!show_debug)
  return;
  
 va_start( args, fmt );
 vsnprintf( buf, SFS_DEBUG_MAX_BUF, fmt, args );
 va_end( args );

 if (!is_daemon)
  fprintf( SFS_DEBUG_OUT, "%s[%d]: %s\n", module_name, getpid(), buf );
 else
  syslog( LOG_INFO, "%s[%d]: %s", module_name, getpid(), buf );
}

