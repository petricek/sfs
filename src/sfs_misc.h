/*
 * sfs_misc.h
 *
 * Miscellaneous functions header.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>,
 *
 */

#ifndef _SFS_MISC_H
#define _SFS_MISC_H

#include <sys/types.h>

#include "mrsa.h"
#include "sfs.h"

/*
 * Structures
 *
 */

  // Parsed line from .sfsdir
typedef struct sfsdir_line {
  uid_t uid;
  char file_name[SFS_MAX_PATH];
  char file_key[SFS_MAX_KEY];
} sfsdir_line;


  // Parsed line from .sfsgdir
typedef struct sfsgdir_line {
  uid_t gid;
  char file_name[SFS_MAX_PATH];
  char file_key[SFS_MAX_KEY];
} sfsgdir_line;


  // Parsed line from .sfsadir
typedef struct sfsadir_line {
  char file_name[SFS_MAX_PATH];
  char file_key[SFS_MAX_KEY];
} sfsadir_line;


  // Parsed line from .sfssizes
typedef struct sfssizes_line {
  char file_name[SFS_MAX_PATH];
  off_t size;
} sfssizes_line;


  // Parsed line from /etc/sfs/passwd 
typedef struct passwd_line {
  uid_t uid;
  char user_private_key[SFS_MAX_PATH];
} passwd_line;


  // Parsed line from /etc/sfs/groups 
typedef struct groups_line {
  gid_t gid;
  char group_public_key[SFS_MAX_PATH];
} groups_line;


  // Parsed line from /etc/sfs/gshadow
typedef struct gshadow_line {
  gid_t gid;
  uid_t uid;
  char group_private_key[SFS_MAX_PATH];
} gshadow_line;


/*
 * Functions parsing different config files
 *
 */

  // Parses line of sfsdir 
sfsdir_line * sfs_parse_sfsdir_line(char * line);

  // Parses line of sfsgdir 
  //sfsdir_line * sfs_parse_sfsgdir_line(char * line);

  // Parses line of sfsadir 
sfsadir_line * sfs_parse_sfsadir_line(char * line);

  // Parses line of sfssizes
sfssizes_line * sfs_parse_sfssizes_line(char * line);

  // Parses line of /etc/sfs/groups 
groups_line * sfs_parse_groups_line(char * line);

  // Parses line of /etc/sfs/gshadow
gshadow_line * sfs_parse_gshadow_line(char * line);

  // Parses line of /etc/sfs/passwd 
passwd_line * sfs_parse_passwd_line(char * line);


  // Reads in a line from file
int sfs_read_line( int file, char *buf, int max );

  // Makes a temporary file name
char *sfs_tempname( const char *dir );

  // Conversion from bit array to hex string
char *bit2hex(char *bit_array, int array_length);
  // Conversion from hex string bit array
char *hex2bit(char *hex_string, int array_length);


/*
 * Functions working with .sfsdir
 *
 */

  // from sfsdir decrypts the symetric file key
char *sfs_read_file_key(const char *dir, const char *name, uid_t uid);

  // to sfsdir writes the symetric file key - encrypted
int   sfs_write_file_key(const char *dir, const char *name, uid_t uid, const char *key);

  // from sfsdir deletes the symetric file key for specified user 
int   sfs_delete_file_key(const char *dir, const char *name, uid_t uid);


/*
 * Functions working with .sfsgdir
 *
 */

  // from sfsgdir decrypts the symetric file key
char *sfs_read_g_file_key(const char *dir, const char *name, gid_t gid);

  // to sfsgdir writes the symetric file key - encrypted
int sfs_write_g_file_key(const char *dir, const char *name, gid_t gid, const char *key);

  // from sfsgdir deletes the symetric file key for specified group
int   sfs_delete_g_file_key(const char *dir, const char *name, gid_t gid);


/*
 * Functions working with .sfsadir
 *
 */

  // from sfsadir decrypts the symetric file key
char *sfs_read_a_file_key(const char *dir, const char *name );

  // to sfsadir writes the symetric file key - encrypted
int   sfs_write_a_file_key(const char *dir, const char *name, const char *key);

  // from sfsadir deletes the symetric file key for all 
int   sfs_delete_a_file_key(const char *dir, const char *name );


/*
 * Functions working with .sfssizes
 *
 */

  // from sfssizes reads the file size
off_t sfs_read_file_size( const char *dir, const char *name );

  // to sfsdir writes the symetric file key - encrypted
int   sfs_write_file_size( const char *dir, const char *name, const off_t size );

  // from sfsdir deletes the symetric file key for specified user 
int   sfs_delete_file_size( const char *dir, const char *name );


/*
 * Operations with private key of the specified user
 *
 */

  // Reads in private key of the specified user
char *sfs_read_user_private_key( uid_t uid );
  // Writes out private key of the specified user
int   sfs_write_user_private_key( uid_t uid, const char *privkey );
  // Deletes private key of the specified user
int   sfs_delete_user_private_key( uid_t uid );


/*
 * Operations with private key of the specified group
 *
 */

  // Reads in private key of the specified group
char *sfs_read_group_private_key( gid_t gid, uid_t uid );
  // Writes out private key of the specified group
int   sfs_write_group_private_key( gid_t gid, uid_t uid, const char *privkey );
  // Deletes private key of the specified group
int   sfs_delete_group_private_key( gid_t gid, uid_t uid );


/*
 * Operations with public key of the specified user
 *
 */

  // Reads in public key of the specified user
char *sfs_read_user_public_key( uid_t uid );
  // Writes out public key of the specified user
int   sfs_write_user_public_key( uid_t uid, const char *pubkey );
  // Deletes public key of the specified user
int   sfs_delete_user_public_key( uid_t uid );


/*
 * Operations with public key of the specified group
 *
 */

  // Reads in public key of the specified group
char *sfs_read_group_public_key( gid_t gid );
  // Writes out public key of the specified group
int   sfs_write_group_public_key( gid_t gid, const char *pubkey );
  // Deletes public key of the specified group
int   sfs_delete_group_public_key( gid_t gid );


/*
 * Work with keys of all users
 *
 */

  // Reads in public key of all users
char *sfs_read_all_public_key();
  // Reads in private key of all users
char *sfs_read_all_private_key( uid_t uid );
  // Deletes public key of all users
int sfs_delete_all_public_key();
  // Deletes private key of all users encrypted for specified user
int sfs_delete_all_private_key(uid_t uid);
  // Writes out private key of all users encrypted for specified user
int sfs_write_all_private_key(uid_t uid, const char * hex_private_key);
  // Writes out public key of all users 
int sfs_write_all_public_key(const char * hex_private_key);


#endif

