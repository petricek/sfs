/*
 * sfs_debug.h
 *
 * Debugging and info functions prototypes.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */

#ifndef _SFS_DEBUG_H
#define _SFS_DEBUG_H

#define SFS_DEBUG_MAX_BUF	1024
#define SFS_DEBUG_OUT		stderr

#define SFS_DEBUG

  // Show debugging outputs?
extern int show_debug;

  // Debugging outputs
void  sfs_deb( int is_daemon, const char *module_name, const char *fmt, ... );

  // Totally discard debugging stuff
#ifndef SFS_DEBUG

#define sfs_debug( args... )
#define _DE
#define DEB(x)

#else

  // Send debugging outputs to std or syslog
#ifdef _SFS_DEBUG_DAEMON

  // Debugging outputs going to stdout/stderr
#define sfs_debug( name, fmt, args... ) \
 sfs_deb( 1, name, fmt, ## args )

#else

  // Debugging outputs going to syslog daemon
#define sfs_debug( name, fmt, args... ) \
 sfs_deb( 0, name, fmt, ## args )

#endif


  // Incremental debugging outputs
#define DEB(x) //sfs_debug( x, "debug: %d, %d", debug++, __LINE__ )
#define _DE //int debug = 0;

#endif


#endif
