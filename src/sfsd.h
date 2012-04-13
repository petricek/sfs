/*
 * sfsd.h
 *
 * The main SFS daemon structures and functions prototypes
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#ifndef _SFSD_H
#define _SFSD_H

#include "sfs.h"


/*
 * SFS daemon functions
 *
 */

  // Main loop of the daemon
int   sfsd_main( void );
  // Initializes the daemon
int   sfsd_init( void );
  // Destroys the daemon
int   sfsd_destroy( void );
  // Resatarts the daemon
void  sfsd_restart( void );
  // Signal handling
void  sfsd_signal( int signum );
  // Start up as a daemon
int   sfsd_daemon_setup( void );


/*
 * SFS daemon requests
 *
 */

  // Initializing request
int   sfs_init_requests( void );
  // Open file request
int   sfs_open_request( struct sfs_open_request *req );
  // Close file request
int   sfs_close_request( struct sfs_close_request *req );
  // Read from file request
int   sfs_read_request( struct sfs_read_request *req );
  // Write to file request
int   sfs_write_request( struct sfs_write_request *req );
  // File chmod request
int   sfs_chmod_request( struct sfs_chmod_request *req );
  // File fchmod request
int   sfs_fchmod_request( struct sfs_fchmod_request *req );
  // User login request
int   sfs_login_request( struct sfs_login_request *req );
  // Change password request
int   sfs_chpass_request( struct sfs_chpass_request *req  );
  // Say something nice to daemon request
int   sfs_string_request( const char *str );
  // Dump user database request
int   sfs_dump_request( void  );
  // Is file in internal structures request
int   sfs_is_request( struct sfs_is_request *req );
  // Set file size request
int   sfs_setsize_request( struct sfs_size_request *req );
  // Get file size request
int   sfs_getsize_request( struct sfs_size_request *req );


/*
 * Functions working with internal demon structure containing files
 *
 */

  // Adds file to internal demon structures
int   sfs_add_file( pid_t pid, int fd, const char *key, off_t size, const char *dir, const char *name );


/*
 * Functions working with internal demon structure containing file keys
 *
 */

  // Returns file key from internal demon structures
char *sfs_get_file_key( pid_t pid, int fd );

  // Deletes file key from internal demon structures
int   sfs_del_file_key( pid_t pid, int fd );


/*
 * Functions working with internal demon structure containing file sizes
 *
 */

  // Returns file key from internal demon structures
int   sfs_get_file_size( pid_t pid, int fd, off_t *size );

  // Adds file key to internal demon structures
int   sfs_set_file_size( pid_t pid, int fd, off_t size );


/*
 * Functions working with internal demon structure containing users
 *
 */

  // Find user which is currently logged in
struct sfs_user *sfs_find_user( uid_t uid );


#endif

