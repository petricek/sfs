/*
 * sfsd_req.c
 *
 * SFS daemon request function calls.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#include <string.h>

#define _SFS_DEBUG_DAEMON

#include <errno.h> 
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sfs.h"
#include "sfsd.h"
#include "sfs_misc.h"
#include "sfs_debug.h"
#include "sfs_secure.h"

/*
 * Internal structures
 *
 */

//----------------------------------------------------------------------------
// users
// ~~~~~
// Internal structure containing users
//----------------------------------------------------------------------------
struct sfs_user users[SFS_MAX_USERS];
int last_user  = 0;

//----------------------------------------------------------------------------
// files
// ~~~~~
// Internal structure containing files
//----------------------------------------------------------------------------
struct sfs_file files[SFS_MAX_FILES];

//----------------------------------------------------------------------------
// last_file
// ~~~~~~~~~
// Last file allocated
//----------------------------------------------------------------------------
int last_file = 0;


/*
 * Requests
 *
 */


//----------------------------------------------------------------------------
// sfs_init_request()
// ~~~~~~~~~~~~~~~~~~
// Handle init request
// Status: finished
//----------------------------------------------------------------------------
int
sfs_init_requests( void )
{
  int i;
  
  for (i=0;i<SFS_MAX_FILES;i++)
    files[i].key[0] = 0;
  return SFS_REPLY_OK;
}

#undef DE
#define DE DEB( "sfs_open_request" );

//----------------------------------------------------------------------------
// sfs_open_request()
// ~~~~~~~~~~~~~~~~~~
// Handle open request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_open_request( struct sfs_open_request *req )
{
  char *ekey, *dkey, *ekey_bin;
  struct sfs_user *user;
  rsa_key *rk;
  int len;
  off_t size;
_DE
  
DE
//  sfs_debug( "sfsd_open_request", "open: %d, %s%s.", req->pid, req->dir, req->name );
  if (last_file >= SFS_MAX_FILES) {
    sfs_debug( "sfsd_open_request", "maximum number of files reached" );
    return SFS_REPLY_FAIL;
  }

DE
  user = sfs_find_user( req->uid );
  if (!user) {
    sfs_debug( "sfsd_open_request", "find user %d error", req->uid );
    return SFS_REPLY_FAIL;
  }

DE
  ekey = sfs_read_file_key( req->dir, req->name, req->uid );
  rk = sfs_asym_parse_key( user->key );

  if (!ekey) {
    ekey = sfs_read_g_file_key( req->dir, req->name, req->gid );
    rk = sfs_asym_parse_key( user->gkey );
    if (!ekey) {
      ekey = sfs_read_a_file_key( req->dir, req->name );
      rk = sfs_asym_parse_key( user->akey );
      if (!ekey) {
        sfs_debug( "sfsd_open_request", "file %s%s key read error -> O.K. (NOT encrypted)", req->dir, req->name );
        return SFS_REPLY_OK;
      }
    }
  }

DE
  if (!rk) {
    sfs_debug( "sfsd_open_request", "rk error" );
    return SFS_REPLY_FAIL;
  }

DE
  ekey_bin = hex2bit( ekey, 0 );
  if (!ekey_bin) {
    sfs_debug( "sfsd_open_request", "bin_ekey error" );
    return SFS_REPLY_FAIL;
  }

DE
  len = strlen( ekey ) / 2;
  dkey = sfs_asym_decrypt( rk, ekey_bin, &len );
  if (!dkey) {
    sfs_debug( "sfsd_open_request", "decrypt key error" );
    return SFS_REPLY_FAIL;
  }

DE /*
  dkey = bit2hex( dkey_bin, len );
  if (!dkey) {
    sfs_debug( "sfsd_open_request", "bin_dkey error" );
    return SFS_REPLY_FAIL;
  } */

DE
  if ((size = sfs_read_file_size( req->dir, req->name )) == -1) {
    sfs_debug( "sfsd_open_request", "size getting error" );
    return SFS_REPLY_FAIL;
  }

DE
  if (sfs_add_file( req->pid, req->fd, dkey, size, req->dir, req->name ) != SFS_REPLY_OK) {
    sfs_debug( "sfsd_open_request", "add key error" );
    return SFS_REPLY_FAIL;
  }

//  sfs_debug( "sfsd_open_request", "opened: %d, %d, %s", req->pid, req->fd, dkey );
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_close_request()
// ~~~~~~~~~~~~~~~~~~~
// Handle close request
// Status: finished
//----------------------------------------------------------------------------
int
sfs_close_request( struct sfs_close_request *req )
{
//  sfs_debug( "sfsd_close_request", "close: %d, %d .", req->pid, req->fd );
  
  if (sfs_del_file_key( req->pid, req->fd) != SFS_REPLY_OK) {
    sfs_debug( "sfsd_close_request", "file delete error" );
    return SFS_REPLY_FAIL;
  }

  return SFS_REPLY_OK;
}


#undef DE
#define DE DEB( "sfs_read_request" );

//----------------------------------------------------------------------------
// sfs_read_request()
// ~~~~~~~~~~~~~~~~~~
// Handle read request
// Status: almost finished
//----------------------------------------------------------------------------
int
sfs_read_request( struct sfs_read_request *req )
{
  char *key, *ret;
  unsigned int i;
//  char *tmp_buf = (char*) malloc( req->count+1 );
_DE

//  sfs_debug( "sfsd_read_request", "read: %d, %d, %d.", req->pid, req->fd, req->count );
  
  key = sfs_get_file_key( req->pid, req->fd );
  if (!key) {
    // File is not registered in daemon's structures
    sfs_debug( "sfsd_read_request", "file key not found!!!" );
    return SFS_REPLY_FAIL;
  }

DE /*
  if (tmp_buf) {
    for (i=0; i<req->count; i++)
      tmp_buf[i] = req->buf[i];
    tmp_buf[i] = 0;
    sfs_debug( "sfs_read_request", "key: %s, count: %d, buf: %s", key, req->count, tmp_buf );
  } */

DE // count=0 !!!!
  ret = sfs_sym_decrypt( key, req->buf, req->count );
  if (!ret) {
    sfs_debug( "sfsd_read_request", "decryption failed!!!" );
    return SFS_REPLY_FAIL;
  }
  
DE
  for (i=0; i<req->count; i++) {
//    sfs_debug( "sfs_read_request", "%d: %c,%c", i, req->buf[i], ret[i] );
    req->buf[i] = ret[i];
  }

DE
  return SFS_REPLY_OK;
}


#undef DE
#define DE DEB( "sfs_write_request" );

//----------------------------------------------------------------------------
// sfs_write_request()
// ~~~~~~~~~~~~~~~~~~~
// Handle write request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_write_request( struct sfs_write_request *req )
{
  char *key, *ret;
  int i, cnt = req->count;
_DE

  sfs_debug( "sfsd_write_request", "write: %d, %d, %d.", req->pid, req->fd, req->count );

DE
  key = sfs_get_file_key( req->pid, req->fd );
  if (!key) {
    sfs_debug( "sfsd_read_request", "file key not found!!!" );
    return SFS_REPLY_FAIL;
  }

DE
  ret = sfs_sym_encrypt( key, req->buf, &cnt );

  sfs_debug( "sfsd_write_request", "write: %d, %d.", cnt, ret );

DE
  for (i=0; i<cnt; i++)
    req->buf[i] = ret[i];

  req->count = cnt;
DE  
  return SFS_REPLY_OK;
}


#undef DE
#define DE DEB( "sfs_chmod_request" );

//----------------------------------------------------------------------------
// sfs_chmod_request()
// ~~~~~~~~~~~~~~~~~~~
// Handle chmod request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_chmod_request( struct sfs_chmod_request *req )
{
  char *dkey_hex=NULL, *ekey=NULL, *ekey_bin=NULL, *temppath=NULL,*enc_buf = NULL, *ekey_hex=NULL;
  char buf[SFS_MAX_PATH];  
  //struct sfs_login_request *user=NULL;
  rsa_key *privkey=NULL;
  rsa_key *pubkey=NULL;
  int size,len,file,tempfile,ret, filesize, orig_filesize;
  struct sfs_user * user=NULL;
_DE
  
//  sfs_debug( "sfsd_chmod_request", "chmod: %s%s, %d, %d.", req->dir, req->name, req->uid, req->mode );
  
  user = sfs_find_user( req->uid );
  if (!user) {
    sfs_debug( "sfsd_chmod_request", "find user %d error", req->uid );
    return SFS_REPLY_FAIL;
  }
DE

 /*
  * file is NOT encrypted && change 'encrypted' attribute ON
  *
  */
  
  if (req->mode) {
    if (sfs_read_file_key( req->dir, req->name, req->uid )) {
//      sfs_debug( "sfsd_chmod_request1", "MODE got:%d", req->mode );
      sfs_debug( "sfsd_chmod_request1", "file already encrypted" );
      return SFS_REPLY_FAIL;
    }

DE    
    // Generates random file key (hex)
    dkey_hex = sfs_sym_generate_key( SFS_FILE_KEY_SIZE );
    if (!dkey_hex) {
      sfs_debug( "sfsd_chmod_request1", "random key error" );
      return SFS_REPLY_FAIL;
    }
    len = strlen( dkey_hex );
//    sfs_debug( "sfsd_chmod_request1", "%s%s", req->dir, req->name );
//    sfs_debug( "sfsd_chmod_request1", "generated filekey:%s", dkey_hex );

// USER ---------------------------- //

DE
    // Gets user public key
    pubkey = sfs_asym_parse_key( sfs_read_user_public_key(req->uid) );
    if (!pubkey) {
      sfs_debug( "sfsd_chmod_request1", "pubkey parse error" );
      return SFS_REPLY_FAIL;
    }

DE 
    // Encrypts file key with user public key
    ekey_bin = sfs_asym_encrypt( pubkey, dkey_hex, &len );
    if (!ekey_bin) {
      sfs_debug( "sfsd_chmod_request1", "encrypt file key error" );
      return SFS_REPLY_FAIL;
    }
DE
    // Converts encrypted file key to hex
    ekey_hex = bit2hex(ekey_bin,len);
    if (!ekey_hex) {
      sfs_debug( "sfsd_chmod_request1", "ekey error" );
      return SFS_REPLY_FAIL;
    }
//    sfs_debug( "sfsd_chmod_request1", "encrypted filekey:%s\n", ekey_hex );

DE
    // and writes it to .sfsdir
    if (sfs_write_file_key( req->dir, req->name, req->uid, ekey_hex ) == -1) {
      sfs_debug( "sfsd_chmod_request1", "write key error" );
      return SFS_REPLY_FAIL;
    }

// GROUP --------------------------------//

DE      
    if(pubkey)
    {
      free(pubkey);
      pubkey = NULL;
    }
    pubkey = sfs_asym_parse_key(sfs_read_group_public_key(req->gid));
    if (!pubkey) {
      sfs_debug( "sfsd_chmod_request1", "pubkey parse error" );
      return SFS_REPLY_FAIL;
    }

DE      
    // Encrypts file key with group public key
    len = strlen(dkey_hex);
    if(ekey_bin)
    {
      free(ekey_bin);
      ekey_bin = NULL;
    }
    ekey_bin = sfs_asym_encrypt( pubkey, dkey_hex, &len );
    if (!ekey_bin) {
      sfs_debug( "sfsd_chmod_request1", "encrypt file key error" );
      return SFS_REPLY_FAIL;
    }
DE
    // Converts encrypted file key to hex
    if(ekey_hex)
    {
      free(ekey_hex);
      ekey_hex = NULL;
    }
    ekey_hex = bit2hex(ekey_bin,len);
    if (!ekey_hex) {
      sfs_debug( "sfsd_chmod_request1", "ekey error" );
      return SFS_REPLY_FAIL;
    }
//    sfs_debug( "sfsd_chmod_request1", "encrypted filekey:%s\n", ekey_hex );

DE
    // and writes it to .sfsgdir
    if(sfs_write_g_file_key( req->dir, req->name, req->gid, ekey_hex ) == -1) {
      sfs_debug( "sfsd_chmod_request1", "write key error" );
      return SFS_REPLY_FAIL;
    }

// ALL  --------------------------------//

DE      
    if(pubkey)
    {
      free(pubkey);
      pubkey = NULL;
    }
    pubkey = sfs_asym_parse_key(sfs_read_all_public_key());
    if (!pubkey) {
      sfs_debug( "sfsd_chmod_request1", "rk error" );
      return SFS_REPLY_FAIL;
    }

DE      
    // Encrypts file key with all public key
    len = strlen(dkey_hex);
    if(ekey_bin)
    {
      free(ekey_bin);
      ekey_bin = NULL;
    }
    ekey_bin = sfs_asym_encrypt( pubkey, dkey_hex, &len );
    if (!ekey_bin) {
      sfs_debug( "sfsd_chmod_request1", "encrypt file key error" );
      return SFS_REPLY_FAIL;
    }
DE
    // Converts encrypted file key to hex
    if(ekey_hex)
    {
      free(ekey_hex);
      ekey_hex = NULL;
    }
    ekey_hex = bit2hex(ekey_bin,len);
    if (!ekey_hex) {
      sfs_debug( "sfsd_chmod_request1", "ekey error" );
      return SFS_REPLY_FAIL;
    }
//    sfs_debug( "sfsd_chmod_request1", "encrypted filekey:%s\n", ekey_hex );

DE
    // and writes it to .sfsadir
    if (sfs_write_a_file_key( req->dir, req->name, ekey_hex ) == -1) {
      sfs_debug( "sfsd_chmod_request1", "write key error" );
      return SFS_REPLY_FAIL;
    }

// Encryption of the whole file --------//

DE      
    // encrypt the whole file using sfs_sym_encrypt() 
    sprintf( buf, "%s%s", req->dir, req->name);
    
DE
    file = __open( buf, O_EXCL|O_RDONLY );
    if (file == -1) {
      sfs_debug( "sfsd_chmod_request1", "error openning %s: %d", buf, errno );
      return SFS_REPLY_FAIL;
    }
    
DE
    temppath = sfs_tempname( req->dir );
    if (!temppath) {
      sfs_debug( "sfsd_chmod_request1", "error getting tempname" );
      __close( file );
      return SFS_REPLY_FAIL;
    }
    
DE
    tempfile = __open( temppath, O_WRONLY|O_CREAT|O_EXCL, req->rights /*S_IREAD|S_IWRITE*/ );
    if (tempfile == -1) {
      sfs_debug( "sfsd_chmod_request1", "error openning %s: %d", temppath, errno );
      __close( file );
      return SFS_REPLY_FAIL;
    }
    

DE
    while ((size = read( file, buf, BF_BLOCK_SIZE ))) {
      if (size == -1) {
        sfs_debug( "sfsd_chmod_request1", "read error" );
        __close( file );
        __close( tempfile );
        return SFS_REPLY_FAIL;
      }
      enc_buf = sfs_sym_encrypt( dkey_hex, buf, &size );
      __write( tempfile, enc_buf, BF_BLOCK_SIZE );
    }

DE
    __close( file );
    __close( tempfile );
    sprintf( buf, "%s%s", req->dir, req->name);
    rename( temppath, buf );
    if(ret!=0)
      sfs_debug("sfs_chmod_request1","rename error: %s -> %s :%d", temppath, buf, ret);
    // restores rights to the file 
    ret = __chmod(buf, req->rights);
//    sfs_debug("sfs_chmod_request1","changing back rights");
    if(ret == -1)
      sfs_debug("sfs_chmod_request1","error setting back rights");
    // if demon runs as root it changes back owner of file
    ret = __chown(buf,req->uid,-1);
    if(ret == -1)
      sfs_debug("sfs_chmod_request1","error changing back owner");

DE
    if (sfs_write_file_size( req->dir, req->name, req->size ) == -1) {
      sfs_debug( "sfsd_chmod_request1", "write size error" );
      return SFS_REPLY_FAIL;
    }
  }
  
 /*
  * file IS encrypted && change 'encrypted' attribute OFF
  *
  */
  
  else {
    ekey = sfs_read_file_key( req->dir, req->name, req->uid );
    if (!ekey) {
      sfs_debug( "sfsd_chmod_requesto", "get file key error or file is NOT encrypted" );
      return SFS_REPLY_FAIL;
    }

DE
    len = strlen( ekey );
    ekey_bin = hex2bit( ekey, 0 );
    if (!ekey_bin) {
      sfs_debug( "sfsd_chmod_request0", "ekey_bin error" );
      return SFS_REPLY_FAIL;
    }
    len = len/2;
    
DE
    privkey = sfs_asym_parse_key( user->key );
    if (!privkey) {
      sfs_debug( "sfsd_chmod_request0", "privkey parse error" );
      return SFS_REPLY_FAIL;
    }

DE
//    sfs_debug( "sfsd_chmod_request0", "encrypted filekey:%s", ekey);
//     sfs_debug( "sfsd_chmod_request0", "user->key:%s",user->key );
DE
//    sfs_debug( "sfsd_chmod_request0", "len: %d, RSA_BLOCK_SIZE:%d, len%RSA:%d", len, RSA_BLOCK_SIZE,len % RSA_BLOCK_SIZE);
    dkey_hex = sfs_asym_decrypt( privkey, ekey_bin, &len );
    if (!dkey_hex) {
      sfs_debug( "sfsd_chmod_request0", "decrypt key error" );
      return SFS_REPLY_FAIL;
    }

DE    

    //dkey_hex = bit2hex(dkey_bin,len);
    //if (!dkey_hex) {
    //  sfs_debug( "sfsd_chmod_request0", "bit2hex error" );
    //  return SFS_REPLY_FAIL;
    //}
//    sfs_debug( "sfsd_chmod_request0", "decrypted filekey:%s", dkey_hex );

DE    
    sprintf( buf, "%s%s", req->dir, req->name);
//    sfs_debug( "sfsd_chmod_request0", "%s%s", req->dir, req->name );
    file = __open( buf, O_EXCL|O_RDONLY );
    if (file == -1) {
      sfs_debug( "sfsd_chmod_request0", "buf - error openning %s: %d", buf, errno );
      return SFS_REPLY_FAIL;
    }
    
DE
    temppath = sfs_tempname( req->dir );
    if (!temppath) {
      sfs_debug( "sfsd_chmod_request0", "error getting tempname" );
      __close( file );
      return SFS_REPLY_FAIL;
    }
    
DE
    tempfile = __open( temppath, O_WRONLY|O_CREAT|O_EXCL, req->rights /*S_IREAD|S_IWRITE*/ );
    if (tempfile == -1) {
      sfs_debug( "sfsd_chmod_request0", "temppath - error openning %s: %d", temppath, errno );
      __close( file );
      return SFS_REPLY_FAIL;
    }
    
    /* decrypt the whole file using sfs_decrypt(buf,count,dkey) */
DE
    filesize = 0;
    orig_filesize = sfs_read_file_size(req->dir, req->name);
    if(orig_filesize == -1)
    {
      sfs_debug( "sfsd_chmod_request0", "error getting file size" );
      return SFS_REPLY_FAIL;
    }
    while ((size = read( file, buf, BF_BLOCK_SIZE ))) {
      if (size == -1) {
        sfs_debug( "sfsd_chmod_request0", "read error" );
        __close( file );
        __close( tempfile );
        return SFS_REPLY_FAIL;
      }
      enc_buf = sfs_sym_decrypt( dkey_hex, buf, BF_BLOCK_SIZE );
      if((filesize + size) > orig_filesize)
      {
        __write( tempfile, enc_buf, orig_filesize-filesize );
      }
      else
      {
        __write( tempfile, enc_buf, BF_BLOCK_SIZE );
      }
      filesize += size;
    }

DE
DE
    __close( file );
    __close( tempfile );
    sprintf( buf, "%s%s", req->dir, req->name);
    ret = rename( temppath, buf );
    if(ret!=0)
      sfs_debug("sfs_chmod_request0","rename error: %s -> %s : %d", temppath, buf, ret); 

    // restores rights to the file 
    ret = __chmod(buf, req->rights);
    if(ret == -1)
      sfs_debug("sfs_chmod_request1","error changing back owner");
    // if demon runs as root it changes back owner of file
    ret = __chown(buf,req->uid,-1);
    if(ret == -1)
      sfs_debug("sfs_chmod_request1","error setting back rights");

DE
    if (sfs_delete_file_key( req->dir, req->name, req->uid ) == -1) {
      sfs_debug( "sfsd_chmod_request0", "delete file key error" );
      return SFS_REPLY_FAIL;
    }

DE
    if (sfs_delete_g_file_key( req->dir, req->name, req->gid ) == -1) {
      sfs_debug( "sfsd_chmod_request0", "delete g_file key error" );
      return SFS_REPLY_FAIL;
    }

DE
    if (sfs_delete_a_file_key( req->dir, req->name ) == -1) {
      sfs_debug( "sfsd_chmod_request0", "delete a_file key error" );
      return SFS_REPLY_FAIL;
    }

DE
    if (sfs_delete_file_size( req->dir, req->name ) == -1) {
      sfs_debug( "sfsd_chmod_request0", "delete file size error" );
      return SFS_REPLY_FAIL;
    }
  }
  
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_fchmod_request()
// ~~~~~~~~~~~~~~~~~~~~
// Handle  request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_fchmod_request( struct sfs_fchmod_request *req )
{
  sfs_debug( "sfsd_fchmod_request", "fchmod: %p.", req );
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_login_request()
// ~~~~~~~~~~~~~~~~~~~
// Handle  request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_login_request( struct sfs_login_request *req )
{
  char *ekey=NULL, *ekey_bin=NULL, *dkey_bin=NULL, *dkey=NULL;
  rsa_key *user_privkey=NULL;
  int len=0;
  
//  sfs_debug( "sfsd_login_request", "login: %s, %d, %s, %d, %d", req->name, strlen(req->key), req->key, req->uid, req->gid );
  if (last_user >= SFS_MAX_USERS) {
    sfs_debug( "sfsd", "maximum number of users reached" );
    return SFS_REPLY_FAIL;
  }
  users[last_user].uid = req->uid;
  users[last_user].gid = req->gid;
  strncpy( users[last_user].name, req->name, SFS_MAX_USER );
  strncpy( users[last_user].key, req->key, SFS_MAX_KEY );

/// Find and decrypt group key ///

  ekey = sfs_read_group_private_key( req->gid, req->uid );
  if (!ekey) {
    sfs_debug( "sfsd_login_request", "read g priv key error" );
    return SFS_REPLY_FAIL;
  }
//  sfs_debug( "sfsd_login_request", "ekey: %d, %s", strlen(ekey), ekey );

  user_privkey = sfs_asym_parse_key( req->key );
  if (!user_privkey) {
    sfs_debug( "sfsd_login_request", "sfs_asym_parse_key error" );
    return SFS_REPLY_FAIL;
  }

//  sfs_debug( "sfsd_login_request", "Key parsed - OK" );
  len = strlen( ekey ) / 2;
  ekey_bin = hex2bit( ekey, 0 );
  if (!ekey_bin) {
    sfs_debug( "sfsd_login_request", "hex2bit error" );
    return SFS_REPLY_FAIL;
  }

//  sfs_debug( "sfsd_login_request", "Key hex2bit - OK" );

  dkey_bin = sfs_asym_decrypt( user_privkey, ekey_bin, &len );
  if (!dkey_bin) {
    sfs_debug( "sfsd_login_request", "sfs_asym_decrypt error" );
    return SFS_REPLY_FAIL;
  }

//  sfs_debug( "sfsd_login_request", "Key decrypted - OK" );

  dkey = bit2hex( dkey_bin, len );
  if (!dkey) {
    sfs_debug( "sfsd_login_request", "bit2hex error" );
    return SFS_REPLY_FAIL;
  }

//  sfs_debug( "sfsd_login_request", "decrypted group key - len: %d, key: %s", strlen(dkey), dkey );
  strncpy( users[last_user].gkey, dkey, SFS_MAX_KEY );

/// etc. for all ///
/*
  if(ekey)
  {
    free(ekey);
    ekey = NULL;
  }
*/
  ekey = sfs_read_all_private_key( req->uid );
  if (!ekey) {
    sfs_debug( "sfsd_login_request", "read a priv key error" );
    return SFS_REPLY_FAIL;
  }
//  sfs_debug( "sfsd_login_request", "ekey: %d, %s", strlen(ekey), ekey );

  len = strlen( ekey ) / 2;
  if(ekey_bin)
  {
    free(ekey_bin);
    ekey_bin = NULL;
  }
  ekey_bin = hex2bit( ekey, 0 );
  if (!ekey_bin) {
    sfs_debug( "sfsd_login_request", "hex2bit2 error" );
    return SFS_REPLY_FAIL;
  }

  if(dkey_bin)
  {
    free(dkey_bin);
    dkey_bin = NULL;
  }
  dkey_bin = sfs_asym_decrypt( user_privkey, ekey_bin, &len );
  if (!dkey_bin) {
    sfs_debug( "sfsd_login_request", "sfs_asym_decrypt2 error" );
    return SFS_REPLY_FAIL;
  }

  if(dkey)
  {
    free(dkey);
    dkey = NULL;
  }
  dkey = bit2hex( dkey_bin, len );
  if (!dkey) {
    sfs_debug( "sfsd_login_request", "bit2hex2 error" );
    return SFS_REPLY_FAIL;
  }

//  sfs_debug( "sfsd_login_request", "Decrypted all key - len: %d, key: %s", strlen(dkey), dkey );
  strncpy( users[last_user].akey, dkey, SFS_MAX_KEY );

  last_user++;
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_chpass_request()
// ~~~~~~~~~~~~~~~~~~~~
// Handle chpass request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_chpass_request( struct sfs_chpass_request *req  )
{
  sfs_debug( "sfsd", "chpass: %p.", req );
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_string_request()
// ~~~~~~~~~~~~~~~~~~~~
// Handle string request
// Status: finished
//----------------------------------------------------------------------------
int
sfs_string_request( const char *str )
{
  sfs_debug("sfsd", "string: %s.", str);
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_dump_request()
// ~~~~~~~~~~~~~~~~~~
// Handle dump request
// Status: finished
//----------------------------------------------------------------------------
int
sfs_dump_request( void  )
{
  int i;
  
//  sfs_debug( "sfsd", "dumping db." );
  for (i=0;i<last_user;i++)
//   sfs_debug( "sfsd", "  %s %s %d %d", users[i].name, users[i].key, users[i].uid, users[i].gid );
  sfs_debug( "sfsd", "dumping finished." );
  return SFS_REPLY_OK;
}


//----------------------------------------------------------------------------
// sfs_is_request()
// ~~~~~~~~~~~~~~~~
// Handle is request
// Status: finished
//----------------------------------------------------------------------------
int
sfs_is_request( struct sfs_is_request *req )
{
  char *f;
  
//  sfs_debug( "sfsd_is_request", "is: %d, %d.", req->fd, req->pid );
  f = sfs_get_file_key( req->pid, req->fd );
  
  if(f) {
//   sfs_debug( "sfsd_is_request", "is: %d, %d: YES.", req->fd, req->pid );
    return SFS_REPLY_ENCRYPTED;
  }
  else {
//    sfs_debug( "sfsd_is_request", "is: %d, %d: NO.", req->fd, req->pid );
    return SFS_REPLY_OK;
  }
}


//----------------------------------------------------------------------------
// sfs_getsize_request()
// ~~~~~~~~~~~~~~~~~~~~~
// Handle getsize request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_getsize_request( struct sfs_size_request *req )
{
  int ret;

//  sfs_debug( "sfsd_getsize_req", "%d, %d, %d, %d.", req->pid, req->uid, req->fd, req->size );
  ret = sfs_get_file_size( req->pid, req->fd, &(req->size) );
//  sfs_debug( "sfsd_getsize_req", "ret(%d) %d, %d, %d, %d.", ret, req->pid, req->uid, req->fd, req->size );

  return ret;
}


//----------------------------------------------------------------------------
// sfs_setsize_request()
// ~~~~~~~~~~~~~~~~~~~~~
// Handle setsize request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs_setsize_request( struct sfs_size_request *req )
{
//  sfs_debug( "sfsd_setsize_req", "%d, %d, %d, %d.", req->pid, req->uid, req->fd, req->size );
  sfs_set_file_size( req->pid, req->fd, req->size );

  return SFS_REPLY_OK;
}


/*

//----------------------------------------------------------------------------
// sfs__request()
// ~~~~~~~~~~~~~~
// Handle  request
// Status: NOT finished
//----------------------------------------------------------------------------
int
sfs__request( struct sfs__request *req )
{
  sfs_debug( "sfsd", ": ." );
  return SFS_REPLY_OK;
}

*/


/*
 * Methods that work with internal structure containing user informations
 *
 */

//----------------------------------------------------------------------------
// sfs_find_user()
// ~~~~~~~~~~~~~~~
// returns from internal structure of demon the user info for particular user
// Status: finished
//----------------------------------------------------------------------------
struct sfs_user*
sfs_find_user( uid_t uid )
{
  int i;
  
  for (i=0;i<last_user;i++)
    if (users[i].uid == uid)
      return &(users[i]);
  return NULL;
}


/*
 * Methods that work with internal structure containing file informations
 *
 */

//----------------------------------------------------------------------------
// sfs_add_file()
// ~~~~~~~~~~~~~~
// Adds file to internal structure of demon
// Status: finished
//----------------------------------------------------------------------------
int
sfs_add_file( pid_t pid, int fd, const char *key, off_t size, const char *dir, const char *name )
{
  int i;
  
  for (i=0;i<SFS_MAX_FILES;i++)
    if (files[i].key[0] == 0)
      break;
  if (i >= SFS_MAX_FILES) {
    sfs_debug( "sfsd_add_file", "maximum number of files reached!!!" );
    return SFS_REPLY_FAIL;
  }

  if (i >= last_file) {
//    sfs_debug( "sfsd_add_file", "last file: %d, i: %d", last_file, i );
    last_file++;
  }

  files[i].pid = pid;
  files[i].fd = fd;
  files[i].size = size;
  strncpy( files[i].key, key, SFS_MAX_PATH );
  strncpy( files[i].dir, dir, SFS_MAX_PATH );
  strncpy( files[i].name, name, SFS_MAX_PATH );

  return SFS_REPLY_OK;
}


/*
 * Methods that work with internal structure containing file informations
 *
 */

//----------------------------------------------------------------------------
// sfs_get_file_key()
// ~~~~~~~~~~~~~~~~~~
// returns from internal structure of demon the symetric key for file
// Status: finished
//----------------------------------------------------------------------------
char*
sfs_get_file_key( pid_t pid, int fd )
{
  int i;
  
  for (i=0;i<last_file;i++) {
//    sfs_debug( "sfs_get_file_key", "%d: %d,%d", i, files[i].pid, files[i].fd );
    if ((files[i].pid == pid) && (files[i].fd == fd))
      return files[i].key;
  }
  return NULL;
}


//----------------------------------------------------------------------------
// sfs_del_file_key()
// ~~~~~~~~~~~~~~~~~~
// Removes file key from internal structure of demon
// Status: finished
//----------------------------------------------------------------------------
int
sfs_del_file_key( pid_t pid, int fd )
{
  int i;
  
  for (i=0;i<last_file;i++) {
//    sfs_debug( "sfs_del_file_key", "%d: %d,%d", i, files[i].pid, files[i].fd );
    if ((files[i].pid == pid) && (files[i].fd == fd)) {
      files[i].key[0] = 0;
      return SFS_REPLY_OK;
    }
  }
  return SFS_REPLY_FAIL;
}


/*
 * Methods that work with internal structure containing file informations
 *
 */

//----------------------------------------------------------------------------
// sfs_get_file_size()
// ~~~~~~~~~~~~~~~~~~~
// returns from internal structure of demon the file size for file
// Status: finished
//----------------------------------------------------------------------------
int
sfs_get_file_size( pid_t pid, int fd, off_t *size )
{
  int i;
  
  for (i=0;i<last_file;i++) {
//    sfs_debug( "sfs_get_file_size", "%d: %d,%d", i, files[i].pid, files[i].fd );
    if ((files[i].pid == pid) && (files[i].fd == fd)) {
      *size = files[i].size;
      return SFS_REPLY_OK;
    }
  }
  return SFS_REPLY_FAIL;
}


//----------------------------------------------------------------------------
// sfs_set_file_size()
// ~~~~~~~~~~~~~~~~~~~
// sets from internal structure of demon the file size for file
// Status: finished
//----------------------------------------------------------------------------
int
sfs_set_file_size( pid_t pid, int fd, off_t size )
{
  int i;
  
  for (i=0;i<last_file;i++) {
//    sfs_debug( "sfs_set_file_size", "%d: %d,%d,%d", i, files[i].pid, files[i].fd, files[i].size );
    if ((files[i].pid == pid) && (files[i].fd == fd)) {
      files[i].size = size;
      if (sfs_write_file_size( files[i].dir, files[i].name, size) != SFS_REPLY_OK) {
        sfs_debug( "sfsd_set_file_size", "writing size error" );
        return SFS_REPLY_FAIL;
      }
      return SFS_REPLY_OK;
    }
  }
  return SFS_REPLY_FAIL;
}


