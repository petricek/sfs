/*
 * sfs_lib.h
 *
 * Miscellaneous library functions header.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#ifndef _SFS_LIB_H
#define _SFS_LIB_H

#include "sfs.h"

#ifndef BF_BLOCK_SIZE
#define BF_BLOCK_SIZE 8
#endif

#ifndef SFS_BF_BLOCK_SIZE
#define SFS_BF_BLOCK_SIZE 8
#endif

extern int sfs_lib_srand;


  // Enlarges the region of a file to contain just complete 
  // BF_BLOCK_SIZE byte blocks
sfs_offset *sfs_generate_aligned_offset( struct sfs_offset *off );

  // Parses path to dir and name using getcwd if necessary
file_location *sfs_parse_file_path( const char *path );

  // Ask daemon if the opened file is encrypted or not
int  sfs_is_encrypted( int fd, uid_t uid, pid_t pid );

  // Return authorization key
long sfs_auth( const char *path );


#endif

