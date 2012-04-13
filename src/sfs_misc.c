/*
 * sfs_misc.c
 *
 * Miscellaneous functions.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>,
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/msg.h>
#include <sys/stat.h>
#include <sys/types.h>

#define _SFS_DEBUG_DAEMON

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_misc.h"
#include "sfs_debug.h"
#include "sfs_secure.h"


//****************************************************************************
//                     BIT & HEX
//****************************************************************************

// *********************************************************************** 
// bit2hex()
// ~~~~~~~~~
// Converts bit array to null terminated string with hex notation of array
// Status: finished
// *********************************************************************** 
char *
bit2hex(char * bit_array, int array_length)
{
  char *hex_string;
  int i =0;
  uchar l=0,h=0;
  
  hex_string = (char*) malloc(array_length*2+1);
  if (!hex_string) {
    // sfs_debug( "bit2hex", "memory error" );
    return NULL;
  }
  
  for(i=0;i<array_length;i++)
  {
    l = (uchar)bit_array[i] & 0x0F;
    h = (uchar)bit_array[i] & 0xF0;
    h >>= 4;
    l = (uchar)("0123456789abcdef"[l]);
    h = (uchar)("0123456789abcdef"[h]);
    hex_string[2*i]=(char)l;
    hex_string[2*i+1]=(char)h;
  }
  hex_string[2*i] = 0;
  
  return hex_string;
}


// *********************************************************************** 
// hex2bit()
// ~~~~~~~~~
// Converts null terminated string with hex notation to an array
// Status: finished
// *********************************************************************** 
char*
hex2bit(char *hex_string, int array_length)
{
  char *bit_array;
  int i =0;
  uchar l,h;
  
  if(array_length == 0)
    array_length = strlen(hex_string);

  bit_array = (char*) malloc(array_length*2+1);
  if (!hex_string) {
    // sfs_debug( "hex2bit", "memory error" );
    return NULL;
  }

  if(bit_array == NULL)
    bit_array = (char *)malloc(array_length);

  while((l = hex_string[i]) && (h = hex_string[i+1]))
  {
    l = l < 'a' ? l - '0' : l - ('a' - 10);
    h = h < 'a' ? h - '0' : h - ('a' - 10);
    h = (uchar)h;
    l = (uchar)l;
    h<<=4;
    bit_array[i/2] = l | h;
    
    i =  i + 2 ;
  }
  array_length = i / 2;
  
  return bit_array;
}


//****************************************************************************
//                     FILES KEYS - USERS
//****************************************************************************

//****************************************************************************
// sfs_read_file_key()
// ~~~~~~~~~~~~~~~~~~~
// Returns symetric key for file - from .sfsdir
// Status: finished
//****************************************************************************
char*
sfs_read_file_key(const char *dir, const char *name, uid_t uid)
{
  int key_file;
  char sfsdir_file[SFS_MAX_PATH], line[SFS_MAX_PATH];
  sfsdir_line * sfsdir_line;
   
  strncpy( sfsdir_file, dir, SFS_MAX_PATH );
  strcat( sfsdir_file, SFS_UDIR_FILE );
  
//  sfs_debug( "sfs_read_file_key", "sfsdir_file: %s", sfsdir_file );

  key_file = __open( sfsdir_file, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_read_file_key", "cannot open key file: %s.", sfsdir_file );
    return NULL;
  }

  for(;;) {  
    if (sfs_read_line( key_file, line, SFS_MAX_PATH ) == -1) {
      sfs_debug( "sfs_read_file_key", "cannot read from key file." );
      __close( key_file );
      return NULL;
    }
    
//    sfs_debug( "sfs_read_file_key", "!: %p:%s", sfsdir_file, line );
    
    if ((sfsdir_line = sfs_parse_sfsdir_line( line )) == NULL) {
      sfs_debug( "sfs_read_file_key", "cannot found key." );
      __close( key_file );
      return NULL;
    }
    
//    sfs_debug( "sfs_read_file_key", "uid: %d, sk.uid:%d", uid, sfsdir_line->uid );
//    sfs_debug( "sfs_read_file_key", "name: %s, sk.name:%s", sfsdir_file, sfsdir_line->file_name );
    
    if ((uid == sfsdir_line->uid) && !(strncmp( name, sfsdir_line->file_name, SFS_MAX_PATH ))) {
//      sfs_debug( "sfs_read_file_key", "found!" );
      break;
    }
  }

  __close( key_file );
  return strdup( sfsdir_line->file_key );
}


//****************************************************************************
// sfs_write_file_key()
// ~~~~~~~~~~~~~~~~~~~~
// Stores file key in .sfsdir 
// Status: finished
//****************************************************************************
int
sfs_write_file_key( const char *dir, const char *name, uid_t uid, const char *key )
{
  int key_file;
  char buf[SFS_MAX_PATH];

  if (sfs_read_file_key( dir, name, uid )) {
    sfs_debug( "sfs_write_file_key", "key already exists" );
    return -1;
  }
  
  strncpy( buf, dir, SFS_MAX_PATH );
  strcat( buf, SFS_UDIR_FILE );
  
//  sfs_debug( "sfs_write_file_key", "buf: %s", buf );

  key_file = __open( buf, O_WRONLY|O_APPEND|O_CREAT, S_IREAD|S_IWRITE );
  if (key_file == -1) {
    sfs_debug( "sfs_write_file_key", "cannot open key file: %s.", buf );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%d:%s:%s\n", uid, name, key );

  if (__write( key_file, buf, strlen( buf ) ) == -1) {
    sfs_debug( "sfs_write_file_key", "cannot write to file (%s).", buf );
    return -1;
  }

  __close( key_file );
 
  return SFS_REPLY_OK;
}


//****************************************************************************
// sfs_delete_file_key()
// ~~~~~~~~~~~~~~~~~~~~~
// Deletes file key from file .sfsdir
// Status: finished
//****************************************************************************
int
sfs_delete_file_key( const char *dir, const char *name, uid_t uid )
{
  int key_file, tmp_file, ret, found = 0, len;
  char keyfn[SFS_MAX_PATH], *tmpfn=NULL, buf[SFS_MAX_PATH], read_buf[SFS_MAX_PATH];
  
  if (!sfs_read_file_key( dir, name, uid )) {
    sfs_debug( "sfs_delete_file_key", "key not found" );
    return -1;
  }

  strncpy( keyfn, dir, SFS_MAX_PATH );
  strcat( keyfn, SFS_UDIR_FILE );
  
  key_file = __open( keyfn, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_delete_file_key", "cannot open key file: %s.", keyfn );
    return -1;
  }
/*
  srand( time( 0 ) );  
  strncpy( tmpfn, dir, SFS_MAX_PATH );
  sprintf( buf, "sfs_%d", rand() );
  strcat( tmpfn, buf );
*/
  tmpfn = tempnam(dir,"sfs");
  
//  sfs_debug( "sfs_delete_file_key", "tmpfn: %s", tmpfn );

  tmp_file = __open( tmpfn, O_CREAT|O_EXCL|O_WRONLY, S_IREAD|S_IWRITE );
  if (tmp_file == -1) {
    sfs_debug( "sfs_delete_file_key", "cannot open tmp file: %s.", tmpfn );
    __close( key_file );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%d:%s:\n", uid, name );

/* copy to another file, without line consisting of "buf..." */

  for (;;) {
    ret = sfs_read_line( key_file, read_buf, SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_delete_file_key", "read_line error: %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_delete_file_key", "file not found: %s%s/%d.", dir, name, uid );
        __close( key_file );
        __close( tmp_file );
        return -1;
      }
      else
        break;
    }
//    sfs_debug( "sfs_delete_file_key", "read: %s", read_buf );
    if (!strncmp( read_buf, buf, strlen(buf)-1 )) {
//      sfs_debug( "sfs_delete_file_key", "found!" );
      found = 1;
      continue;
    }
    len = strlen( read_buf );
    read_buf[len++] = '\n';
    read_buf[len] = 0;
    if (__write( tmp_file, read_buf, len ) == -1) {
      sfs_debug( "sfs_delete_file_key", "write error %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
  }

  __close( key_file );
  __close( tmp_file );
  
//  sfs_debug( "sfs_delete_file_key", "done: %s, %s.", keyfn, tmpfn );

  if (unlink( keyfn ) == -1) {
    sfs_debug( "sfs_delete_file_key", "unlink error: %d", errno );
    return -1;
  }

  if (rename( tmpfn, keyfn ) == -1) {
    sfs_debug( "sfs_delete_file_key", "rename error: %d", errno );
    return -1;
  }

 
  return SFS_REPLY_OK;
}


//****************************************************************************
//                     FILES KEYS - GROUPS
//****************************************************************************

//****************************************************************************
// sfs_read_g_file_key()
// ~~~~~~~~~~~~~~~~~~~~~
// Returns symetric key for file - from .sfsgdir
// Status: finished
//****************************************************************************
char*
sfs_read_g_file_key(const char *dir, const char *name, gid_t gid)
{
  int key_file;
  char sfsdir_file[SFS_MAX_PATH], line[SFS_MAX_PATH];
  sfsgdir_line * sfsdir_line;
   
  strncpy( sfsdir_file, dir, SFS_MAX_PATH );
  strcat( sfsdir_file, SFS_GDIR_FILE );
  
//  sfs_debug( "sfs_read_g_file_key", "sfsdir_file: %s", sfsdir_file );

  key_file = __open( sfsdir_file, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_read_g_file_key", "cannot open key file: %s.", sfsdir_file );
    return NULL;
  }

  for(;;) {  
    if (sfs_read_line( key_file, line, SFS_MAX_PATH ) == -1) {
      sfs_debug( "sfs_read_g_file_key", "cannot read from key file." );
      __close( key_file );
      return NULL;
    }
    
//    sfs_debug( "sfs_read_g_file_key", "!: %p:%s", sfsdir_file, line );
    
    if ((sfsdir_line = (sfsgdir_line*) sfs_parse_sfsdir_line( line )) == NULL) {
      sfs_debug( "sfs_read_g_file_key", "cannot found key." );
      __close( key_file );
      return NULL;
    }
    
//    sfs_debug( "sfs_read_g_file_key", "gid: %d, sk.gid:%d", gid, sfsdir_line->gid );
//    sfs_debug( "sfs_read_g_file_key", "name: %s, sk.name:%s", sfsdir_file, sfsdir_line->file_name );
    
    if ((gid == sfsdir_line->gid) && !(strncmp( name, sfsdir_line->file_name, SFS_MAX_PATH ))) {
//      sfs_debug( "sfs_read_g_file_key", "found!" );
      break;
    }
  }

  __close( key_file );
  return strdup( sfsdir_line->file_key );
}

//****************************************************************************
// sfs_write_g_file_key()
// ~~~~~~~~~~~~~~~~~~~~
// Stores file key in .sfsgdir 
// Status: nearly finished
//****************************************************************************
int
sfs_write_g_file_key( const char *dir, const char *name, gid_t gid, const char *key )
{
  int key_file;
  char buf[SFS_MAX_PATH];

  if (sfs_read_g_file_key( dir, name, gid )) {
    sfs_debug( "sfs_write_file_key", "key already exists" );
    return -1;
  }
  
  strncpy( buf, dir, SFS_MAX_PATH );
  strcat( buf, SFS_GDIR_FILE );
  
//  sfs_debug( "sfs_write_g_file_key", "buf: %s", buf );

  key_file = __open( buf, O_WRONLY|O_APPEND|O_CREAT, S_IREAD|S_IWRITE );
  if (key_file == -1) {
    sfs_debug( "sfs_write_g_file_key", "cannot open key file: %s.", buf );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%d:%s:%s\n", gid, name, key );

  if (__write( key_file, buf, strlen( buf ) ) == -1) {
    sfs_debug( "sfs_write_g_file_key", "cannot write to file (%s).", buf );
    return -1;
  }

  __close( key_file );
 
  return SFS_REPLY_OK;
}


//****************************************************************************
// sfs_delete_g_file_key()
// ~~~~~~~~~~~~~~~~~~~~~
// Deletes file key from file .sfsgdir
// Status: nearly finished
//****************************************************************************
int
sfs_delete_g_file_key( const char *dir, const char *name, gid_t gid )
{
  int key_file, tmp_file, ret, found = 0, len;
  char keyfn[SFS_MAX_PATH], *tmpfn=NULL, buf[SFS_MAX_PATH], read_buf[SFS_MAX_PATH];
  
  if (!sfs_read_g_file_key( dir, name, gid )) {
    sfs_debug( "sfs_delete_g_file_key", "key not found" );
    return -1;
  }

  strncpy( keyfn, dir, SFS_MAX_PATH );
  strcat( keyfn, SFS_GDIR_FILE );
  
  key_file = __open( keyfn, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_delete_g_file_key", "cannot open key file: %s.", keyfn );
    return -1;
  }
/*
  srand( time( 0 ) );  
  strncpy( tmpfn, dir, SFS_MAX_PATH );
  sprintf( buf, "sfs_%d", rand() );
  strcat( tmpfn, buf );
*/
  tmpfn = tempnam(dir,"sfs");
  
//  sfs_debug( "sfs_delete_g_file_key", "tmpfn: %s", tmpfn );

  tmp_file = __open( tmpfn, O_CREAT|O_EXCL|O_WRONLY, S_IREAD|S_IWRITE );
  if (tmp_file == -1) {
    sfs_debug( "sfs_delete_g_file_key", "cannot open tmp file: %s.", tmpfn );
    __close( key_file );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%d:%s:\n", gid, name );

/* copy to another file, without line consisting of "buf..." */

  for (;;) {
    ret = sfs_read_line( key_file, read_buf, SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_delete_g_file_key", "read_line error: %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_delete_g_file_key", "file not found: %s%s/%d.", dir, name, gid );
        __close( key_file );
        __close( tmp_file );
        return -1;
      }
      else
        break;
    }
//    sfs_debug( "sfs_delete_g_file_key", "read: %s", read_buf );
    if (!strncmp( read_buf, buf, strlen(buf)-1 )) {
//      sfs_debug( "sfs_delete_g_file_key", "found!" );
      found = 1;
      continue;
    }
    len = strlen( read_buf );
    read_buf[len++] = '\n';
    read_buf[len] = 0;
    if (__write( tmp_file, read_buf, len ) == -1) {
      sfs_debug( "sfs_delete_g_file_key", "write error %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
  }

  __close( key_file );
  __close( tmp_file );
  
//  sfs_debug( "sfs_delete_g_file_key", "done: %s, %s.", keyfn, tmpfn );

  if (unlink( keyfn ) == -1) {
    sfs_debug( "sfs_delete_g_file_key", "unlink error: %d", errno );
    return -1;
  }

  if (rename( tmpfn, keyfn ) == -1) {
    sfs_debug( "sfs_delete_file_key", "rename error: %d", errno );
    return -1;
  }
 
  return SFS_REPLY_OK;
}

//****************************************************************************
//                     FILES KEYS - ALL
//****************************************************************************

//****************************************************************************
// sfs_read_a_file_key()
// ~~~~~~~~~~~~~~~~~~~~~
// Returns symetric key for file - from .sfsgdir
// Status: finished
//****************************************************************************
char*
sfs_read_a_file_key(const char *dir, const char *name )
{
  int key_file;
  char sfsdir_file[SFS_MAX_PATH], line[SFS_MAX_PATH];
  sfsadir_line * sfsdir_line;
   
  strncpy( sfsdir_file, dir, SFS_MAX_PATH );
  strcat( sfsdir_file, SFS_ADIR_FILE );
  
//  sfs_debug( "sfs_read_a_file_key", "sfsdir_file: %s", sfsdir_file );

  key_file = __open( sfsdir_file, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_read_a_file_key", "cannot open key file: %s.", sfsdir_file );
    return NULL;
  }

  for(;;) {  
    if (sfs_read_line( key_file, line, SFS_MAX_PATH ) == -1) {
      sfs_debug( "sfs_read_a_file_key", "cannot read from key file." );
      __close( key_file );
      return NULL;
    }
    
//    sfs_debug( "sfs_read_a_file_key", "!: %p:%s", sfsdir_file, line );
    
    if ((sfsdir_line = sfs_parse_sfsadir_line( line )) == NULL) {
      sfs_debug( "sfs_read_a_file_key", "cannot found key." );
      __close( key_file );
      return NULL;
    }
    
//    sfs_debug( "sfs_read_a_file_key", "name: %s, sk.name:%s", sfsdir_file, sfsdir_line->file_name );
    
    if (!(strncmp( name, sfsdir_line->file_name, SFS_MAX_PATH ))) {
//      sfs_debug( "sfs_read_a_file_key", "found!" );
      break;
    }
  }

  __close( key_file );
  return strdup( sfsdir_line->file_key );
}

//****************************************************************************
// sfs_write_a_file_key()
// ~~~~~~~~~~~~~~~~~~~~
// Stores file key in .sfsgdir 
// Status: nearly finished
//****************************************************************************
int
sfs_write_a_file_key( const char *dir, const char *name, const char *key )
{
  int key_file;
  char buf[SFS_MAX_PATH];

  if (sfs_read_a_file_key( dir, name )) {
    sfs_debug( "sfs_write_file_key", "key already exists" );
    return -1;
  }
  
  strncpy( buf, dir, SFS_MAX_PATH );
  strcat( buf, SFS_ADIR_FILE );
  
//  sfs_debug( "sfs_write_a_file_key", "buf: %s", buf );

  key_file = __open( buf, O_WRONLY|O_APPEND|O_CREAT, S_IREAD|S_IWRITE );
  if (key_file == -1) {
    sfs_debug( "sfs_write_a_file_key", "cannot open key file: %s.", buf );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%s:%s\n", name, key );

  if (__write( key_file, buf, strlen( buf ) ) == -1) {
    sfs_debug( "sfs_write_a_file_key", "cannot write to file (%s).", buf );
    return -1;
  }

  __close( key_file );
 
  return SFS_REPLY_OK;
}


//****************************************************************************
// sfs_delete_a_file_key()
// ~~~~~~~~~~~~~~~~~~~~~
// Deletes file key from file .sfsgdir
// Status: nearly finished
//****************************************************************************
int
sfs_delete_a_file_key( const char *dir, const char *name )
{
  int key_file, tmp_file, ret, found = 0, len;
  char keyfn[SFS_MAX_PATH], *tmpfn=NULL, buf[SFS_MAX_PATH], read_buf[SFS_MAX_PATH];
  
  if (!sfs_read_a_file_key( dir, name )) {
    sfs_debug( "sfs_delete_a_file_key", "key not found" );
    return -1;
  }

  strncpy( keyfn, dir, SFS_MAX_PATH );
  strcat( keyfn, SFS_ADIR_FILE );
  
  key_file = __open( keyfn, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_delete_a_file_key", "cannot open key file: %s.", keyfn );
    return -1;
  }
/*
  srand( time( 0 ) );  
  strncpy( tmpfn, dir, SFS_MAX_PATH );
  sprintf( buf, "sfs_%d", rand() );
  strcat( tmpfn, buf );
*/
  tmpfn = tempnam(dir,"sfs");
  
//  sfs_debug( "sfs_delete_a_file_key", "tmpfn: %s", tmpfn );

  tmp_file = __open( tmpfn, O_CREAT|O_EXCL|O_WRONLY, S_IREAD|S_IWRITE );
  if (tmp_file == -1) {
    sfs_debug( "sfs_delete_a_file_key", "cannot open tmp file: %s.", tmpfn );
    __close( key_file );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%s:\n", name );

/* copy to another file, without line consisting of "buf..." */

  for (;;) {
    ret = sfs_read_line( key_file, read_buf, SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_delete_a_file_key", "read_line error: %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_delete_a_file_key", "file not found: %s%s/%d.", dir, name );
        __close( key_file );
        __close( tmp_file );
        return -1;
      }
      else
        break;
    }
//    sfs_debug( "sfs_delete_a_file_key", "read: %s", read_buf );
    if (!strncmp( read_buf, buf, strlen(buf)-1 )) {
//      sfs_debug( "sfs_delete_a_file_key", "found!" );
      found = 1;
      continue;
    }
    len = strlen( read_buf );
    read_buf[len++] = '\n';
    read_buf[len] = 0;
    if (__write( tmp_file, read_buf, len ) == -1) {
      sfs_debug( "sfs_delete_a_file_key", "write error %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
  }

  __close( key_file );
  __close( tmp_file );
  
//  sfs_debug( "sfs_delete_a_file_key", "done: %s, %s.", keyfn, tmpfn );

  if (unlink( keyfn ) == -1) {
    sfs_debug( "sfs_delete_a_file_key", "unlink error: %d", errno );
    return -1;
  }

  if (rename( tmpfn, keyfn ) == -1) {
    sfs_debug( "sfs_delete_file_key", "rename error: %d", errno );
    return -1;
  }
 
  return SFS_REPLY_OK;
}

//****************************************************************************
//                     FILES SIZES
//****************************************************************************

//****************************************************************************
// sfs_read_file_size()
// ~~~~~~~~~~~~~~~~~~~~
// Returns file size - from .sfssizes
// Status: finished
//****************************************************************************
off_t
sfs_read_file_size( const char *dir, const char *name )
{
  int key_file;
  char sfsdir_file[SFS_MAX_PATH], line[SFS_MAX_PATH];
  sfssizes_line * sfsdir_line;
   
  strncpy( sfsdir_file, dir, SFS_MAX_PATH );
  strcat( sfsdir_file, SFS_SIZES_FILE );
  
//  sfs_debug( "sfs_read_file_size", "sfsdir_file: %s", sfsdir_file );

  key_file = __open( sfsdir_file, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_read_file_size", "cannot open key file: %s.", sfsdir_file );
    return -1;
  }

  for(;;) {  
    if (sfs_read_line( key_file, line, SFS_MAX_PATH ) == -1) {
      sfs_debug( "sfs_read_file_size", "cannot read from key file." );
      __close( key_file );
      return -1;
    }
    
//    sfs_debug( "sfs_read_file_size", "!: %p:%s", sfsdir_file, line );
    
    if ((sfsdir_line = sfs_parse_sfssizes_line( line )) == NULL) {
      sfs_debug( "sfs_read_file_size", "cannot found size." );
      __close( key_file );
      return -1;
    }
    
//    sfs_debug( "sfs_read_file_size", "name: %s, sk.name:%s", sfsdir_file, sfsdir_line->file_name );
    
    if (!strncmp( name, sfsdir_line->file_name, SFS_MAX_PATH )) {
//      sfs_debug( "sfs_read_file_size", "found!" );
      break;
    }
  }

  __close( key_file );
  return sfsdir_line->size;
}


//****************************************************************************
// sfs_write_file_size()
// ~~~~~~~~~~~~~~~~~~~~~
// Stores file size to .sfssizes
// Status: finished
//****************************************************************************
int
sfs_write_file_size( const char *dir, const char *name, off_t size )
{
  int key_file;
  char buf[SFS_MAX_PATH];

  if (sfs_read_file_size( dir, name ) != -1) {
    sfs_debug( "sfs_write_file_size", "key already exists" );
    if (sfs_delete_file_size( dir, name ) == -1) {
      sfs_debug( "sfs_write_file_size", "deleting error" );
      return -1;
    }
  }
  
  strncpy( buf, dir, SFS_MAX_PATH );
  strcat( buf, SFS_SIZES_FILE );
  
//  sfs_debug( "sfs_write_file_size", "buf: %s", buf );

  key_file = __open( buf, O_WRONLY|O_APPEND|O_CREAT, S_IREAD|S_IWRITE );
  if (key_file == -1) {
    sfs_debug( "sfs_write_file_size", "cannot open key file: %s.", buf );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%s:%d\n", name, size );

  if (__write( key_file, buf, strlen( buf ) ) == -1) {
    sfs_debug( "sfs_write_file_size", "cannot write to file (%s).", buf );
    return -1;
  }

  __close( key_file );
 
  return SFS_REPLY_OK;
}


//****************************************************************************
// sfs_delete_file_size()
// ~~~~~~~~~~~~~~~~~~~~~~
// Deletes file size from file .sfssizes
// Status: finished
//****************************************************************************
int
sfs_delete_file_size( const char *dir, const char *name )
{
  int key_file, tmp_file, ret, found = 0, len;
  char keyfn[SFS_MAX_PATH], *tmpfn, buf[SFS_MAX_PATH], read_buf[SFS_MAX_PATH];
  
  if (sfs_read_file_size( dir, name ) == -1) {
    sfs_debug( "sfs_delete_file_size", "key not found" );
    return -1;
  }

  strncpy( keyfn, dir, SFS_MAX_PATH );
  strcat( keyfn, SFS_SIZES_FILE );
  
  key_file = __open( keyfn, O_RDONLY );
  if (key_file == -1) {
    sfs_debug( "sfs_delete_file_size", "cannot open key file: %s.", keyfn );
    return -1;
  }
/*
  srand( time( 0 ) );  
  strncpy( tmpfn, dir, SFS_MAX_PATH );
  sprintf( buf, "sfs_%d", rand() );
  strcat( tmpfn, buf );
*/

  tmpfn = tempnam(dir,"sfs");
  
//  sfs_debug( "sfs_delete_file_size", "tmpfn: %s", tmpfn );

  tmp_file = __open( tmpfn, O_CREAT|O_EXCL|O_WRONLY, S_IREAD|S_IWRITE );
  if (tmp_file == -1) {
    sfs_debug( "sfs_delete_file_size", "cannot open tmp file: %s.", tmpfn );
    __close( key_file );
    return -1;
  }
  
  snprintf( buf, SFS_MAX_PATH, "%s:\n", name );

/* copy to another file, without line consisting of "buf..." */

  for (;;) {
    ret = sfs_read_line( key_file, read_buf, SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_delete_file_size", "read_line error: %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_delete_file_size", "file not found: %s%s.", dir, name );
        __close( key_file );
        __close( tmp_file );
        return -1;
      }
      else
        break;
    }
//    sfs_debug( "sfs_delete_file_size", "read: %s", read_buf );
    if (!strncmp( read_buf, buf, strlen(buf)-1 )) {
//      sfs_debug( "sfs_delete_file_size", "found!" );
      found = 1;
      continue;
    }
    len = strlen( read_buf );
    read_buf[len++] = '\n';
    read_buf[len] = 0;
    if (__write( tmp_file, read_buf, len ) == -1) {
      sfs_debug( "sfs_delete_file_size", "write error %d.", errno );
      __close( key_file );
      __close( tmp_file );
      return -1;
    }
  }

  __close( key_file );
  __close( tmp_file );
  
//  sfs_debug( "sfs_delete_file_size", "done: %s, %s.", keyfn, tmpfn );

  if (unlink( keyfn ) == -1) {
    sfs_debug( "sfs_delete_file_size", "unlink error: %d", errno );
    return -1;
  }

  if (rename( tmpfn, keyfn ) == -1) {
    sfs_debug( "sfs_delete_file_size", "rename error: %d", errno );
    return -1;
  }

 
  return SFS_REPLY_OK;
}


//****************************************************************************
//                     PARSE
//****************************************************************************

//****************************************************************************
// sfs_parse_sfsdir_line()
// ~~~~~~~~~~~~~~~~~~~~~~~
// Parses line of .sfsdir
// Status: finished
//****************************************************************************
sfsdir_line*
sfs_parse_sfsdir_line( char *buffer )
{
  char *token, *buf, *buf2;
  long id;
  sfsdir_line *sl;
  
  sl = (sfsdir_line*) malloc( sizeof( sfsdir_line ) );
  if (!sl) {
    sfs_debug( "sfs_readkey", "not enough memory" );
    return NULL;
  }
  
  buf = strdup( buffer );
  if (!buf) {
    sfs_debug( "sfs_readfilekey", "not enough memory" );
    return NULL;
  }

  token = strtok( buf, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_readfilekey", "no tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_readfilekey", "token: %s", token );
  
  id = strtol( token, &buf2, 0 );
  if (buf2 == buf) {
    sfs_debug( "sfs_readfilekey", "error reading id" );
    free( buf );
    return NULL;
  }

  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_readfilekey", "no more tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_readfilekey", "token: %s", token );
  
  strncpy( sl->file_name, token, SFS_MAX_PATH );

  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_readfilekey", "no more tokens found 2." );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_readfilekey", "token: %s", token );
  
  strncpy( sl->file_key, token, SFS_MAX_KEY );
  sl->uid = (uid_t) id;
  free( buf );
  return sl;
}


//****************************************************************************
// sfs_parse_sfsadir_line()
// ~~~~~~~~~~~~~~~~~~~~~~~
// Parses line of .sfsadir
// Status: finished
//****************************************************************************
sfsadir_line*
sfs_parse_sfsadir_line( char *buffer )
{
  char *token, *buf;
  sfsadir_line *sl;
  
  sl = (sfsadir_line*) malloc( sizeof( sfsadir_line ) );
  if (!sl) {
    sfs_debug( "sfs_parse", "not enough memory" );
    return NULL;
  }
  
  buf = strdup( buffer );
  if (!buf) {
    sfs_debug( "sfs_parse", "not enough memory" );
    return NULL;
  }

  token = strtok( buf, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse", "no tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse", "token: %s", token );
  
  strncpy( sl->file_name, token, SFS_MAX_PATH );

  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse", "no more tokens found 2." );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse", "token: %s", token );
  
  strncpy( sl->file_key, token, SFS_MAX_KEY );
  free( buf );
  return sl;
}


//****************************************************************************
// sfs_parse_sfssizes_line()
// ~~~~~~~~~~~~~~~~~~~~~~~~~
// Parses line of .sfssizes
// Status: finished
//****************************************************************************
sfssizes_line*
sfs_parse_sfssizes_line( char *buffer )
{
  char *token, *buf, *buf2;
  long size;
  sfssizes_line *sl;
  
//  sfs_debug( "sfs_parse", "%s", buffer );
  sl = (sfssizes_line*) malloc( sizeof( sfssizes_line ) );
  if (!sl) {
    sfs_debug( "sfs_parse", "not enough memory" );
    return NULL;
  }
  
  buf = strdup( buffer );
  if (!buf) {
    sfs_debug( "sfs_parse", "not enough memory" );
    return NULL;
  }

  token = strtok( buf, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse", "no more tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse", "token: %s", token );
  
  strncpy( sl->file_name, token, SFS_MAX_PATH );

  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse", "no tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse", "token: %s", token );
  
  size = strtol( token, &buf2, 0 );
  if (buf2 == buf) {
    sfs_debug( "sfs_parse", "error reading id" );
    free( buf );
    return NULL;
  }

  sl->size = size;
  free( buf );
  return sl;
}


//****************************************************************************
// sfs_parse_groups_line()
// ~~~~~~~~~~~~~~~~~~~~~~~
// Parses line of /etc/sfs/groups
// Status: finished
//****************************************************************************
groups_line*
sfs_parse_groups_line( char * line )
{
  char *token, *buf, *buf2;
  long id;
  groups_line *gl;
  gl = (groups_line *)malloc(sizeof(groups_line));

  buf = strdup(line);
  if (!buf) {
    sfs_debug( "sfs_parse_groups_line", "not enough memory" );
    return NULL;
  }

  token = strtok( buf, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse_groups_line", "no tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse_groups_line", "token: %s", token );
  
  id = strtol( token, &buf2, 0 );
  if (buf2 == buf) {
    sfs_debug( "sfs_parse_groups_line", "error reading uid" );
    free( buf );
    return NULL;
  }

  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse_groups_line", "no more tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse_groups_line", "token: %s", token );
  
  gl->gid = (gid_t) id;
  strncpy( gl->group_public_key, token, SFS_MAX_KEY );
  free( buf );
    
  return gl;
}


//****************************************************************************
// sfs_parse_gshadow_line()
// ~~~~~~~~~~~~~~~~~~~~~~~~
// Parses line of /etc/sfs/gshadow
// Status: finished
//****************************************************************************
gshadow_line*
sfs_parse_gshadow_line( char * line )
{
  char *token, *buf, *buf2;
  long id;
  gshadow_line *gl;
  gl = (gshadow_line *)malloc(sizeof(gshadow_line));

  buf = strdup(line);
  if (!buf) {
    sfs_debug( "sfs_parse_gshadow_line", "not enough memory" );
    return NULL;
  }

  token = strtok( buf, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse_gshadow_line", "no tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse_gshadow_line", "token: %s", token );
  
  id = strtol( token, &buf2, 0 );
  if (buf2 == buf) {
    sfs_debug( "sfs_parse_gshadow_line", "error reading uid" );
    free( buf );
    return NULL;
  }

  gl->gid = (gid_t) id;
  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse_gshadow_line", "no tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse_gshadow_line", "token: %s", token );
  
  id = strtol( token, &buf2, 0 );
  if (buf2 == buf) {
    sfs_debug( "sfs_parse_gshadow_line", "error reading uid" );
    free( buf );
    return NULL;
  }

  gl->uid = (uid_t) id;
  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_parse_gshadow_line", "no more tokens found" );
    free( buf );
    return NULL;
  }
  
//  sfs_debug( "sfs_parse_gshadow_line", "token: %s", token );
  
  strncpy( gl->group_private_key, token, SFS_MAX_KEY );
  free( buf );
    
  return gl;
}


#define DE //DEB( "parse_passwd" );

//****************************************************************************
// sfs_parse_passwd_line()
// ~~~~~~~~~~~~~~~~~~~~~~~
// Parses line of /etc/sfs/passwd
// Status: finished
//****************************************************************************
passwd_line*
sfs_parse_passwd_line( char *buffer )
{
  char *token, *buf, *buf2;
  long id;
  passwd_line *pl;
//_DE

DE  
  pl = (passwd_line*) malloc( sizeof( passwd_line ) );
  if (!pl) {
    sfs_debug( "sfs_readkey", "not enough memory" );
    return NULL;
  }
  
DE
  buf = strdup( buffer );
  if (!buf) {
    sfs_debug( "sfs_readkey", "not enough memory" );
    return NULL;
  }

DE
  token = strtok( buf, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_readkey", "no tokens found" );
    free( buf );
    return NULL;
  }
  
DE
//  sfs_debug( "sfs_readkey", "token: %s", token );
  
  id = strtol( token, &buf2, 0 );
  if (buf2 == buf) {
    sfs_debug( "sfs_readkey", "error reading uid" );
    free( buf );
    return NULL;
  }

DE
  token = strtok( NULL, SFS_DELIMITER );
  if (!token) {
    sfs_debug( "sfs_readkey", "no more tokens found" );
    free( buf );
    return NULL;
  }
  
DE
//  sfs_debug( "sfs_readkey", "token: %s", token );
  
  pl->uid = (uid_t) id;
  strncpy( pl->user_private_key, token, SFS_MAX_KEY );

DE
  free( buf );
  return pl;
}


//****************************************************************************
//                             USER - PUBLIC
//****************************************************************************

//****************************************************************************
// sfs_read_user_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in public key of the specified user
// Status: finished
//****************************************************************************
char*
sfs_read_user_public_key( uid_t uid )
{
  int passwd, ret;
  char *line;
  passwd_line *pl;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_read_user_public_public_key", "memory error" );
    return NULL;
  }
  
  passwd = __open( SFS_PASSWD_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_read_user_public_key", "error opening %s", SFS_PASSWD_FILE );
    return NULL;
  }

  for(;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_user_public_key", "read error" );
      free( line );
      __close( passwd );
      return NULL;
    }
    if (!ret) {
      sfs_debug( "sfs_read_user_public_key", "eof" );
      free( line );
      __close( passwd );
      return NULL;
    }
    if ((pl = sfs_parse_passwd_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_public_key", "eof???" );
      free( line );
      return NULL;
    }
    if (pl->uid == uid)
      break;
  }

  __close( passwd );
  return pl->user_private_key;
}


//****************************************************************************
// sfs_write_user_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in public key of the specified user
// Status: finished
//****************************************************************************
int
sfs_write_user_public_key( uid_t uid, const char *hex_public_key )
{
  int passwd, ret;
  char buf[SFS_MAX_PATH];

  // No public key yet
  if (sfs_read_user_public_key( uid ))
    sfs_delete_user_public_key( uid );
    
  sprintf( buf, "%d%s%s\n", uid, SFS_DELIMITER, hex_public_key );
  passwd = __open( SFS_PASSWD_FILE, O_CREAT|O_APPEND|O_WRONLY, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_write_user_public_key", "error opening %s", SFS_PASSWD_FILE );
    return -1;
  }
  ret = __write( passwd, buf, strlen( buf ) );
  if (ret == -1) {
    sfs_debug( "sfs_write_user_public_key", "write error" );
    __close( passwd );
    return -1;
  }
 
  __close( passwd );
  return ret;
}


//****************************************************************************
// sfs_delete_user_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Deletes public key of the specified user
// Status: almost finished
//****************************************************************************
int
sfs_delete_user_public_key( uid_t uid )
{
  int passwd, tempfile, ret, found = 0;
  char *line, *temppath, buf[SFS_MAX_PATH];
  passwd_line *pl;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_delete_user_public_key", "memory error" );
    return -1;
  }
  
  passwd = __open( SFS_PASSWD_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_user_public_key", "error opening %s", SFS_PASSWD_FILE );
    free( line );
    return -1;
  }

  temppath = tempnam(NULL, "sfs");
  if (temppath == NULL) {
    sfs_debug( "sfs_delete_user_public_key", "error getting tempname" );
    free( line );
    __close( passwd );
    return -1;
  }
 
  tempfile = __open( temppath, O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_user_public_key", "error opening %s", temppath );
    __close( passwd );
    free( line );
    return -1;
  }

  for(;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_user_public_key", "read error" );
      __close( passwd );
      __close( tempfile );
      free( line );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_read_user_public_key", "eof" );
        __close( passwd );
        __close( tempfile );
        free( line );
        return -1;
      }
      else
        break;
    }
    if ((pl = sfs_parse_passwd_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_public_key", "eof???" );
        __close( passwd );
        __close( tempfile );
      free( line );
      return -1;
    }

    if (pl->uid == uid) {
      found = 1;
      continue;
    }
    else {
      sprintf( buf, "%s\n", line);
      __write( tempfile, buf, strlen( buf ) );
    }
  }
  __close( tempfile );
  __close( passwd );
  ////////////////////////////////////////////////////unlink() ??????
  ret = rename( temppath, SFS_PASSWD_FILE );
  if (ret == -1) {
    sfs_debug( "sfs_delete_user_public_key", "error renaming tempname" );
    return -1;
  }
   
  return 0;
}


//****************************************************************************
//                     USER - PRIVATE
//****************************************************************************

//****************************************************************************
// sfs_read_user_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in private key of the specified user
// Status: finished
//****************************************************************************
char*
sfs_read_user_private_key( uid_t uid )
{
  int passwd, ret;
  char *line;
  passwd_line *pl;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_read_user_private_private_key", "memory error" );
    return NULL;
  }
  
  passwd = __open( SFS_SHADOW_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_read_user_private_key", "error openning %s", SFS_SHADOW_FILE );
    free( line );
    return NULL;
  }

  for (;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_user_private_key", "read error" );
      __close( passwd );
      free( line );
      return NULL;
    }
    if (!ret) {
      sfs_debug( "sfs_read_user_private_key", "eof" );
      __close( passwd );
      free( line );
      return NULL;
    }
    if ((pl = sfs_parse_passwd_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_private_key", "eof???" );
      free( line );
      return NULL;
    }
    if (pl->uid == uid)
      break;
  }

  __close( passwd );
  return pl->user_private_key;
}


//****************************************************************************
// sfs_write_user_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in private key of the specified user
// Status: finished
//****************************************************************************
int
sfs_write_user_private_key( uid_t uid, const char *hex_private_key )
{
  int passwd, ret;
  char buf[SFS_MAX_PATH];

  // No private key yet
  if (sfs_read_user_private_key( uid ))
    sfs_delete_user_private_key( uid );

  sprintf( buf, "%d%s%s\n", uid, SFS_DELIMITER, hex_private_key);
  passwd = __open( SFS_SHADOW_FILE, O_CREAT|O_APPEND|O_WRONLY, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_write_user_private_key", "error opening %s", SFS_SHADOW_FILE );
    return -1;
  }
  ret = __write( passwd, buf, strlen( buf ) );
  if (ret == -1) {
    sfs_debug( "sfs_write_user_private_key", "write error" );
    __close( passwd );
    return -1;
  }
 
  __close( passwd );
  return ret;
}


//****************************************************************************
// sfs_delete_user_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Deletes private key of the specified user
// Status: almost finished
//****************************************************************************
int
sfs_delete_user_private_key( uid_t uid )
{
  int passwd, tempfile, ret, found = 0;
  char *line, *temppath, buf[SFS_MAX_PATH];
  passwd_line *pl;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_delete_user_private_key", "memory error" );
    return -1;
  }
  
  passwd = __open( SFS_SHADOW_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_user_private_key", "error opening %s", SFS_SHADOW_FILE );
    free( line );
    return -1;
  }

  temppath = tempnam(NULL, "sfs");
  if (temppath == NULL) {
    sfs_debug( "sfs_delete_user_private_key", "error getting tempname" );
    free( line );
    __close( passwd );
    return -1;
  }
 
  tempfile = __open( temppath, O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_user_private_key", "error opening %s", temppath );
    __close( passwd );
    free( line );
    return -1;
  }

  for(;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_user_private_key", "read error" );
      __close( passwd );
      __close( tempfile );
      free( line );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_read_user_private_key", "eof" );
        __close( passwd );
        __close( tempfile );
        free( line );
        return -1;
      }
      else
        break;
    }
    if ((pl = sfs_parse_passwd_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_private_key", "eof???" );
        __close( passwd );
        __close( tempfile );
      free( line );
      return -1;
    }

    if (pl->uid == uid) {
      found = 1;
      continue;
    }
    else {
      sprintf( buf, "%s\n", line);
      __write( tempfile, buf, strlen( buf ) );
    }
  }
  __close( tempfile );
  __close( passwd );
  ////////////////////////////////////////////////////unlink() ??????
  ret = rename( temppath, SFS_SHADOW_FILE );
  if (ret == -1) {
    sfs_debug( "sfs_delete_user_private_key", "error renaming tempname" );
    return -1;
  }
   
  return 0;
}


//****************************************************************************
//                     GROUPS - PUBLIC
//****************************************************************************

//****************************************************************************
// sfs_read_group_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in public key of the specified user
// Status: finished
//****************************************************************************
char*
sfs_read_group_public_key( gid_t gid )
{
  int groups, ret;
  char *line=NULL;
  groups_line *gl=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_read_group_public_key", "memory error" );
    return NULL;
  }
  
  groups = __open( SFS_GROUPS_FILE, O_RDONLY );
  if (groups == -1) {
    sfs_debug( "sfs_read_group_public_key", "%s open error", SFS_GROUPS_FILE );
    free( line );
    return NULL;
  }

  for (;;) {
    ret = sfs_read_line( groups, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_group_public_key", "read error" );
      free( line );
      return NULL;
    }
    if (!ret) {
      sfs_debug( "sfs_read_group_public_key", "eof" );
      free( line );
      return NULL;
    }
    if ((gl = sfs_parse_groups_line( line )) == NULL ) {
      sfs_debug( "sfs_read_group_public_key", "eof???" );
      free( line );
      return NULL;
    }
    if (gl->gid == gid)
      break;
  }

  __close( groups );
  return gl->group_public_key;
}


//****************************************************************************
// sfs_write_group_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in public key of the specified user
// Status: finished
//****************************************************************************
int
sfs_write_group_public_key( gid_t gid, const char *hex_public_key )
{
  int groups, ret;
  char buf[SFS_MAX_PATH];

  // Some public key already
  if (sfs_read_group_public_key( gid ))
    sfs_delete_group_public_key( gid );

  groups = __open( SFS_GROUPS_FILE, O_APPEND|O_CREAT|O_WRONLY, S_IREAD|S_IWRITE );
  if (groups == -1) {
    sfs_debug( "sfs_write_group_public_key", "%s open error", SFS_GROUPS_FILE );
    return -1;
  }
  sprintf( buf, "%d%s%s\n", gid, SFS_DELIMITER, hex_public_key );
  ret = __write( groups, buf, strlen( buf ) );

  __close( groups );
  return ret;
}


//****************************************************************************
// sfs_delete_group_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Deletes public key of the specified group
// Status: almost finished
//****************************************************************************
int
sfs_delete_group_public_key( gid_t gid )
{
  int passwd, tempfile, ret, found = 0;
  char *line=NULL, *temppath=NULL, buf[SFS_MAX_PATH];
  groups_line *pl=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_delete_group_public_key", "memory error" );
    return -1;
  }
  
  passwd = __open( SFS_GROUPS_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_group_public_key", "error opening %s", SFS_GROUPS_FILE );
    free( line );
    return -1;
  }

  temppath = tempnam(NULL, "sfs");
  if (temppath == NULL) {
    sfs_debug( "sfs_delete_group_public_key", "error getting tempname" );
    free( line );
    __close( passwd );
    return -1;
  }
 
  tempfile = __open( temppath, O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_group_public_key", "error opening %s", temppath );
    __close( passwd );
    free( line );
    return -1;
  }

  for(;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_group_public_key", "read error" );
      __close( passwd );
      __close( tempfile );
      free( line );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_read_group_public_key", "eof" );
        __close( passwd );
        __close( tempfile );
        free( line );
        return -1;
      }
      else
        break;
    }
    if ((pl = sfs_parse_groups_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_public_key", "eof???" );
        __close( passwd );
        __close( tempfile );
      free( line );
      return -1;
    }

    if (pl->gid == gid) {
      found = 1;
      continue;
    }
    else {
      sprintf( buf, "%s\n", line);
      __write( tempfile, buf, strlen( buf ) );
    }
  }
  __close( tempfile );
  __close( passwd );
  ////////////////////////////////////////////////////unlink() ??????
  ret = rename( temppath, SFS_GROUPS_FILE );
  if (ret == -1) {
    sfs_debug( "sfs_delete_group_public_key", "error renaming tempname" );
    return -1;
  }
   
  return 0;
}

//#define _DE int debug = 0;
//#define DE sfs_debug( "tmp", "debug: %d", debug++ );

//****************************************************************************
//                     GROUPS - PRIVATE
//****************************************************************************

//****************************************************************************
// sfs_read_group_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in private key of the specified user
// Status: finished
//****************************************************************************
char*
sfs_read_group_private_key( gid_t gid, uid_t uid )
{
  int groups, ret;
  char *line=NULL;
  gshadow_line *gl=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_read_group_private_key", "memory error" );
    return NULL;
  }
  
  groups = __open( SFS_GSHADOW_FILE, O_RDONLY );
  if (groups == -1) {
    sfs_debug( "sfs_read_group_private_key", "error openning %s", SFS_GSHADOW_FILE );
    free( line );
    return NULL;
  }

  for (;;) {
    ret = sfs_read_line( groups, line, SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_group_private_key", "read error" );
      free( line );
      __close( groups );
      return NULL;
    }
    if (!ret) {
      sfs_debug( "sfs_read_group_private_key", "eof" );
      free( line );
      __close( groups );
      return NULL;
    }
    if ((gl = sfs_parse_gshadow_line( line )) == NULL ) {
      sfs_debug( "sfs_read_group_private_key", "eof???: %s", line );
      free( line );
      __close( groups );
      return NULL;
    }
    if ((gl->gid == gid) && (gl->uid == uid ))
      break;
  }

  __close( groups );
  return gl->group_private_key;
}


//****************************************************************************
// sfs_write_group_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in private key of the specified user
// Status: finished
//****************************************************************************
int
sfs_write_group_private_key( gid_t gid, uid_t uid, const char *hex_private_key )
{
  int groups, ret;
  char buf[SFS_MAX_PATH+200];
_DE

DE
  // Some private key already present
  if (sfs_read_group_private_key( gid, uid ))
    sfs_delete_group_private_key( gid, uid );

DE
  groups = __open( SFS_GSHADOW_FILE, O_APPEND|O_CREAT|O_RDWR, S_IREAD|S_IWRITE );
  if (groups == -1) {
    sfs_debug( "sfs_write_group_private_key", "error openning %s", SFS_GSHADOW_FILE );
    return -1;
  }

DE
  sprintf( buf, "%d%s%d%s%s\n", gid, SFS_DELIMITER, uid, SFS_DELIMITER, hex_private_key );
//  sfs_debug( "sfs_write_group_private_key", "%d:%s", strlen(buf), buf );

DE
  ret = __write( groups, buf, strlen( buf ) );
//  sfs_debug( "sfs_write_group_private_key", "%d", ret );

DE
  __close( groups );

DE
  return ret;
}


//****************************************************************************
// sfs_delete_group_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Deletes private key of the specified group
// Status: almost finished
//****************************************************************************
int
sfs_delete_group_private_key( gid_t gid, uid_t uid )
{
  int passwd, tempfile, ret, found = 0;
  char *line=NULL, *temppath=NULL, buf[SFS_MAX_PATH];
  gshadow_line *pl=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_delete_group_private_key", "memory error" );
    return -1;
  }
  
  passwd = __open( SFS_GSHADOW_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_group_private_key", "error opening %s", SFS_GSHADOW_FILE );
    free( line );
    return -1;
  }

  temppath = tempnam(NULL, "sfs");
  if (temppath == NULL) {
    sfs_debug( "sfs_delete_group_private_key", "error getting tempname" );
    free( line );
    __close( passwd );
    return -1;
  }
 
  tempfile = __open( temppath, O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_group_private_key", "error opening %s", temppath );
    __close( passwd );
    free( line );
    return -1;
  }

  for(;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_group_private_key", "read error" );
      __close( passwd );
      __close( tempfile );
      free( line );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_read_group_private_key", "eof" );
        __close( passwd );
        __close( tempfile );
        free( line );
        return -1;
      }
      else
        break;
    }
    if ((pl = sfs_parse_gshadow_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_private_key", "eof???" );
        __close( passwd );
        __close( tempfile );
      free( line );
      return -1;
    }

    if ((pl->uid == uid) && (pl->gid == gid )) {
      found = 1;
      continue;
    }
    else {
      sprintf( buf, "%s\n", line);
      __write( tempfile, buf, strlen( buf ) );
    }
  }
  __close( tempfile );
  __close( passwd );
  ////////////////////////////////////////////////////unlink() ??????
  ret = rename( temppath, SFS_GSHADOW_FILE );
  if (ret == -1) {
    sfs_debug( "sfs_delete_group_private_key", "error renaming tempname" );
    return -1;
  }
   
  return 0;
}


//****************************************************************************
//                            ALL - PUBLIC 
//****************************************************************************

//****************************************************************************
// sfs_read_all_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in public key of the specified user
// Status: finished
//****************************************************************************
char*
sfs_read_all_public_key()
{
  int passwd;
  char *line=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_read_all_public_public_key", "memory error" );
    return NULL;
  }
  
  passwd = __open( SFS_ALL_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_read_all_public_key", "error openning %s", SFS_ALL_FILE );
    free( line );
    return NULL;
  }

  if (sfs_read_line( passwd, line, SFS_MAX_PATH ) == -1) {
    sfs_debug( "sfs_read_all_public_key", "read error" );
    free( line );
    __close( passwd );
    return NULL;
  }

  __close( passwd );
  return line;
}


//****************************************************************************
// sfs_write_all_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in public key of the specified user
// Status: finished
//****************************************************************************
int
sfs_write_all_public_key( const char *hex_public_key )
{
  int passwd, ret;
  char buf[SFS_MAX_PATH+200];

  passwd = __open( SFS_ALL_FILE, O_TRUNC|O_CREAT|O_RDWR, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_write_all_public_key", "error openning %s", SFS_ALL_FILE );
    return -1;
  }

  sprintf( buf, "%s\n", hex_public_key );
  ret = __write( passwd, buf, strlen( buf ) );
  __close( passwd );
 
  return ret;
}


//****************************************************************************
// sfs_delete_all_public_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Deletes public key of the specified user
// Status: finished
//****************************************************************************
int
sfs_delete_all_public_key()
{
  return remove( SFS_ALL_FILE );
}


//****************************************************************************
//                     ALL - PRIVATE
//****************************************************************************

//****************************************************************************
// sfs_read_all_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in private key of the specified user
// Status: finished
//****************************************************************************
char*
sfs_read_all_private_key( uid_t uid )
{
  int passwd, ret;
  char *line=NULL;
  passwd_line *pl=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_read_all_private_private_key", "memory error" );
    return NULL;
  }
  
  passwd = __open( SFS_ASHADOW_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_read_all_private_key", "error openning %s", SFS_ASHADOW_FILE );
    return NULL;
  }

  for(;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_read_all_private_key", "read error" );
      __close( passwd );
      free( line );
      return NULL;
    }
    if (!ret) {
      sfs_debug( "sfs_read_all_private_key", "eof" );
      __close( passwd );
      free( line );
      return NULL;
    }
    if ((pl = sfs_parse_passwd_line( line )) == NULL ) {
      sfs_debug( "sfs_read_passwd_private_key", "eof???" );
      __close( passwd );
      free( line );
      return NULL;
    }
    if (pl->uid == uid)
      break;
  }

  __close( passwd );
  return pl->user_private_key;
}


//****************************************************************************
// sfs_write_all_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Reads in private key of the specified user
// Status: finished
//****************************************************************************
int
sfs_write_all_private_key( uid_t uid, const char *hex_private_key )
{
  int passwd, ret;
  char buf[SFS_MAX_PATH+200];

  // No private key yet
  if (sfs_read_all_private_key( uid ))
    sfs_delete_all_private_key( uid );

  sprintf( buf, "%d%s%s\n", uid, SFS_DELIMITER, hex_private_key );
  passwd = __open( SFS_ASHADOW_FILE, O_APPEND|O_CREAT|O_WRONLY, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_write_all_private_key", "error openning %s", SFS_ASHADOW_FILE );
    return -1;
  }

  ret = __write( passwd, buf, strlen( buf ) );
  __close( passwd );
  return ret;
}


//****************************************************************************
// sfs_delete_all_private_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Deletes private key of the specified user
// Status: almost finished
//****************************************************************************
int
sfs_delete_all_private_key( uid_t uid )
{
  int passwd, tempfile, ret, found = 0;
  char *line=NULL, *temppath=NULL, buf[SFS_MAX_PATH];
  passwd_line *pl=NULL;

  line = (char*) malloc( SFS_MAX_PATH );
  if (!line) {
    sfs_debug( "sfs_delete_all_private_private_key", "memory error" );
    return -1;
  }
  
  passwd = __open( SFS_ASHADOW_FILE, O_RDONLY );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_all_private_key", "error openning %s", SFS_ASHADOW_FILE );
    return -1;
  }

  temppath = tempnam( NULL, "sfs" );
  if (temppath == NULL) {
    sfs_debug( "sfs_delete_all_private_key", "error getting tempname" );
    __close( passwd );
    return -1;
  }
 
  tempfile = __open( temppath, O_RDWR|O_CREAT|O_EXCL, S_IREAD|S_IWRITE );
  if (passwd == -1) {
    sfs_debug( "sfs_delete_all_private_key", "error openning %s", temppath );
    __close( passwd );
    return -1;
  }

  for (;;) {
    ret = sfs_read_line( passwd, line ,SFS_MAX_PATH );
    if (ret == -1) {
      sfs_debug( "sfs_delete_all_private_key", "read error" );
      free( line );
      __close( tempfile );
      __close( passwd );
      return -1;
    }
    if (!ret) {
      if (!found) {
        sfs_debug( "sfs_delete_all_private_key", "eof" );
        free( line );
        __close( tempfile );
        __close( passwd );
        return -1;
      }
      else
        break;
    }
    if ((pl = sfs_parse_passwd_line( line )) == NULL ) {
      sfs_debug( "sfs_delete_passwd_private_key", "eof???" );
      free( line );
      __close( tempfile );
      __close( passwd );
      return -1;
    }

    if (pl->uid == uid) {
      found = 1;
      continue;
    }
    else {
      sprintf( buf, "%s\n", line );
      __write( tempfile, buf, strlen( buf ) );
    }
  }

  __close( tempfile );
  __close( passwd );
  free( line );
  ////////////////////////////////////////////////unlink() ???
  ret = rename( temppath, SFS_ASHADOW_FILE );
  if (ret == -1) {
    sfs_debug( "sfs_delete_all_private_key", "error renaming tempname" );
    return -1;
  }
   
  return 0;
}


//****************************************************************************
//                     READLINE
//****************************************************************************

//****************************************************************************
// sfs_read_line()
// ~~~~~~~~~~~~~~~
// Reads a single line from file - without \n
// Status: finished
//****************************************************************************
int
sfs_read_line( int file, char *buf, int max )
{
  int i = 0;
  char b;
  ssize_t ret;
  
  while (i < (max-1)) {
    if ((ret = __read( file, &b, 1)) == -1) {
      sfs_debug( "sfs_read_line", "read error" );
      return -1;
    }
    if (b == '\n') {
      buf[i++] = 0;
      return i;
    }
    else
      buf[i++] = b;
    if (!ret) {
      buf[--i] = 0;
      break;
    }
  }
  if (i == (max-1)) {
    sfs_debug( "sfs_read_line", "maximum reached" );
    buf[i++] = 0;
  }
  return i;
}


//****************************************************************************
//                     TEMPNAME
//****************************************************************************

//****************************************************************************
// sfs_tempname()
// ~~~~~~~~~~~~~~
// Makes a temporary file name in directory dir (/tmp/)
// Status: finished
//****************************************************************************
char*
sfs_tempname( const char *dir )
{
  char *p=NULL;
  
  p = (char*) malloc( SFS_MAX_PATH );
  if(!p) {
    sfs_debug( "sfs_tempname", "memory error: %d", errno );
    return NULL;
  }
  
  srand( time( 0 ) );
  sprintf( p, "%ssfs_%d", dir?dir:"", rand() );
  return p;
}

