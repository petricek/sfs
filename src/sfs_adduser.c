/*
 * sfs_adduser.c
 *
 * Add user to the SFS subsystem.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "sfs.h"
#include "sfs_lib.h"
#include "sfs_misc.h"
#include "sfs_debug.h"
#include "sfs_secure.h"

#undef _DE
#undef DE
#define _DE //int debug = 0;
#define DE //sfs_debug( "sfs_adduser", "debug: %d, %d", debug++, __LINE__ );

//****************************************************************************
// sfs_adduser()
// ~~~~~~~~~~~~
// Add user to SFS subsystem
// Status: almost finished
//****************************************************************************
int
sfs_adduser( void )
{
  char *username=NULL, *pass=NULL, *hex_key=NULL, *bit_key=NULL;
  char *enc_bit_key=NULL, *enc_hex_key=NULL, *random_key=NULL, *root_pass=NULL;
  char buf[SFS_MAX_PATH];
  rsa_key pubkey, privkey, user_privkey, user_pubkey, *root_privkey=NULL, *root_pubkey=NULL;
  char *group_ekey=NULL, *group_ekey_bin=NULL, *group_dkey_bin=NULL;
  char *all_ekey=NULL, *all_ekey_bin=NULL, *all_dkey_bin=NULL;
  char *root_ekey=NULL, *root_ekey_bin=NULL, *root_dkey_bin=NULL, *root_dkey=NULL;
  uid_t uid;
  gid_t gid;
  int len, file, found = 0, ret;
  struct passwd *p=NULL;
_DE

  username = (char *)malloc(SFS_MAX_PATH);

DE

  // get new username
  printf( SFS_LOGIN_USERNAME );
  if (!fgets( username, SFS_MAX_USER, stdin )) {
    sfs_debug( "sfs_adduser", "login is empty" );
    return 1;
  }

DE
  // get new password
  pass = strdup( getpass( SFS_LOGIN_PASSWD ) );
  if (!pass) {
    sfs_debug( "sfs_adduser", "cannot get password" );
    return 1;
  }
//  printf("%s", pass);

DE

  // cut off newline
  username[strlen(username)-1] = 0;
  // Find the new user in /etc/passwd
  while ((p = getpwent())) {
    if (strcmp( username, p->pw_name) == 0) {
      uid = p->pw_uid;
      gid = p->pw_gid;
      found = 1;
      break;
    }
  }
  endpwent();
  
DE
  if (!found) {
    sfs_debug( "sfs_adduser", "user not found in /etc/passwd" );
    return 1;
  }

DE
  // Just root is able to add users to the database
  // this password should be tested against /etc/passwd (coming soon...)
  
  if (uid)
    root_pass = strdup( getpass( "Root's password:" ) );
  else
    root_pass = strdup( pass );
    
  if (!root_pass) {
    sfs_debug( "sfs_adduser", "cannot get root password" );
    return 1;
  }
  
//  printf( "%s", root_pass );

/*
 * Generate authorization key for login and write it to the file at SFS_DIR
 *
 */

DE
  // if authorization key for login does not exist
  if (sfs_auth( SFS_LOGIN_FILE ) == -1) {
    // random auth key
    random_key = sfs_sym_generate_key( SFS_AUTH_KEY_SIZE );
    if (!random_key) {
      sfs_debug( "sfs_adduser", "sym generate error 2" );
      return 1;
    }
    
DE
    // write random key to file named "login"
    sprintf( buf, "%s", SFS_LOGIN_FILE );
    file = __open( buf, O_CREAT|O_EXCL|O_WRONLY, S_IREAD|S_IWRITE );
    if (file == -1) {
      sfs_debug( "sfs_adduser", "file %s creation error: %d", buf, errno );
      return 1;
    }
DE
    if (__write( file, random_key, strlen( random_key ) ) == -1) { 
      sfs_debug( "sfs_adduser", "write error: %d", errno );
      return 1;
    }
    free(random_key);
    random_key = NULL;
    __close( file ); 
  }

/*
 * Generate authorization key and write it to the user's file at SFS_DIR
 *
 */

DE
  // random auth key
  random_key = sfs_sym_generate_key( SFS_AUTH_KEY_SIZE );
  if (!random_key) {
    sfs_debug( "sfs_adduser", "sym generate error" );
    return 1;
  }
  
DE
  // write auth to file named with uid 
  sprintf( buf, "%s/%d", SFS_DIR, uid );
  file = __open( buf, O_CREAT|O_EXCL|O_WRONLY, S_IREAD|S_IWRITE );
  if (file == -1) {
    sfs_debug( "sfs_adduser", "file %s creation error: %d", buf, errno );
    return 1;
  }

DE
  if (__write( file, random_key, strlen( random_key ) ) == -1) { 
    sfs_debug( "sfs_adduser", "write error: %d", errno );
    return 1;
  }
  free(random_key);
  random_key = NULL;
  __close( file ); 
  
DE
  chown( buf, uid, 0 );

/*
 * Generate user's public and private key and write them to appropriate files
 *
 */
  
DE
  // generate a pair of asymetric keys
  
  sfs_asym_generate_key( &user_pubkey, &user_privkey );
  
DE
  // publish public key
  hex_key = sfs_asym_serialize_key( &user_pubkey );
  if (!hex_key) {
    sfs_debug( "sfs_adduser", "asym seri pub error" );
    return 1;
  }

//printf( "pubkey: %s\n", hex_key );
  
DE
  if (sfs_write_user_public_key( uid, hex_key ) == -1) {
    sfs_debug( "sfs_adduser", "error" );
    return 1;
  }
  free(hex_key);
  hex_key = NULL;

  
DE
  // encrypt and write out private key
  hex_key = sfs_asym_serialize_key( &user_privkey );
  if (!hex_key) {
    sfs_debug( "sfs_adduser", "asym seri priv error" );
    return 1;
  }

DE
//printf( "privkey: %s\n", hex_key );
  len = strlen( hex_key)/2;
  bit_key = hex2bit( hex_key, 0 );
  if (!bit_key) {
    sfs_debug( "sfs_adduser", "hex2bit error" );
    return 1;
  }

DE
  enc_bit_key = sfs_sym_encrypt( pass, bit_key, &len );
  if (!enc_bit_key) {
    sfs_debug( "sfs_adduser", "sym decrypt error" );
    return 1;
  }

DE
  enc_hex_key = bit2hex( enc_bit_key, len );
  if (!enc_hex_key) {
    sfs_debug( "sfs_adduser", "bit2hex error" );
    return 1;
  }

DE // 20
  if (sfs_write_user_private_key( uid, enc_hex_key ) == -1) {
    sfs_debug( "sfs_adduser", "w u priv key error" );
    return 1;
  }

  
/*
 * Generate group's public and private key and write them to appropriate files
 * But only if it is not already done
 *
 */
  
  // get root private key
  root_ekey = sfs_read_user_private_key( 0 );
  if (!root_ekey) {
    sfs_debug( "sfs_adduser", "sfs_read_user_private_key error" );
    return 1;
  }
  len = strlen(root_ekey) / 2;
DE
  root_ekey_bin = hex2bit( root_ekey, 0 );
  if (!root_ekey_bin) {
    sfs_debug( "sfs_adduser", "hex2bit error" );
    return 1;
  }
DE
  root_dkey_bin = sfs_sym_decrypt( root_pass, root_ekey_bin, len );
  if (!root_dkey_bin) {
    sfs_debug( "sfs_adduser", "sfs_sym_decrypt error" );
    return 1;
  }
DE
  root_dkey = bit2hex( root_dkey_bin, len );
  if (!root_dkey) {
    sfs_debug( "sfs_adduser", "bit2hex error" );
    return 1;
  }

//  sfs_debug("sfs_adduser","Root password: %s", root_pass);
//  sfs_debug("sfs_adduser","Users password: %s", pass);
//  sfs_debug("sfs_adduser","Encrypted root private key: %s", root_ekey);
//  sfs_debug("sfs_adduser","sym decrypt -> root private key: %s", root_dkey);
  
DE
  root_privkey = sfs_asym_parse_key( root_dkey );
  if (!root_privkey) {
    sfs_debug( "sfs_adduser", "sfs_asym_parse_key error" );
    return 1;
  }
DE
  free(root_dkey);
  root_dkey = NULL;

  // Get root public key
  root_dkey = sfs_read_user_public_key( 0 );
  if (!root_dkey) {
    sfs_debug( "sfs_adduser", "sfs_read_user_public_key error" );
    return 1;
  }
DE
  root_pubkey = sfs_asym_parse_key( root_dkey );
  if (!root_pubkey) {
    sfs_debug( "sfs_adduser", "sfs_asym_parse_key error" );
    return 1;
  }

DE
  // Get group private key
  group_ekey = sfs_read_group_private_key( gid, 0 );
  // if keys for user group (gid) already exist
  if (group_ekey) {
   DE
    len = strlen( group_ekey ) / 2;
    group_ekey_bin = hex2bit( group_ekey, 0 ); 
    if (!group_ekey_bin) {
      sfs_debug( "sfs_adduser", "hex2bit error" );
      return 1;
    }
   DE
    group_dkey_bin = sfs_asym_decrypt( root_privkey, group_ekey_bin, &len );
    if (!group_dkey_bin) {
      sfs_debug( "sfs_adduser", "sfs_asym_decrypt error" );
      return 1;
    }
//    sfs_debug("sfs_adduser","Group private key: %s", bit2hex(group_dkey_bin,len));
   DE
    group_ekey_bin = sfs_asym_encrypt( &user_pubkey, group_dkey_bin, &len );
    if (!group_ekey_bin) {
      sfs_debug( "sfs_adduser", "sfs_asym_encrypt error" );
      return 1;
    }
   DE
    group_ekey = bit2hex( group_ekey_bin, len );
    if (!group_ekey) {
      sfs_debug( "sfs_adduser", "bit2hex error" );
      return 1;
    }
   DE
    ret = sfs_write_group_private_key( gid, uid, group_ekey );
    if (ret == -1) {
      sfs_debug( "sfs_adduser", "error writing group private key" );
      return 1;
    }
  }
  // No keys for group yet - have to generate new
  else {
      
DE
// debug = 21

    // generate a pair of asymetric keys
    sfs_asym_generate_key( &pubkey, &privkey );
   
DE
    // publish public key
    if(hex_key){
      free(hex_key);
      hex_key = NULL;
    }
    hex_key = sfs_asym_serialize_key( &pubkey );
    if (!hex_key) {
      sfs_debug( "sfs_adduser", "asym seri pub error2" );
      return 1;
    }
DE
    if (sfs_write_group_public_key( gid, hex_key ) == -1) {
      sfs_debug( "sfs_adduser", "w g pub error2" );
      return 1;
    }
    
DE
    // encrypt and store private key
    if(hex_key){
      free(hex_key);
      hex_key = NULL;
    }
    hex_key = sfs_asym_serialize_key( &privkey );
    if (!hex_key) {
      sfs_debug( "sfs_adduser", "sfs_asym_serialize_key error" );
      return 1;
    }

//    sfs_debug( "sfs_adduser", "hex_key: %s", hex_key );
  DE
    len = strlen( hex_key ) / 2;
    bit_key = hex2bit( hex_key, 0 );
    if (!bit_key) {
      sfs_debug( "sfs_adduser", "hex2bit error2" );
      return 1;
    }

// Encrypt group private key for user we are adding - if not root
  DE // 32
    if(uid != 0) {
      enc_bit_key = sfs_asym_encrypt( &user_pubkey, bit_key, &len );
      if (!enc_bit_key) {
        sfs_debug( "sfs_adduser", "asym enc priv error2" );
        return 1;
    }
//    sfs_debug( "hell", "%d_%d", 520, len );

    DE
    enc_hex_key = bit2hex( enc_bit_key, len );
    if (!enc_hex_key) {
      sfs_debug( "sfs_adduser", "bit2hex error2" );
      return 1;
    }
  //  sfs_debug( "hello", "hello: %d, %d, %d, %s, %d", gid, uid, len, enc_hex_key, strlen( enc_hex_key) );
    DE

    if (sfs_write_group_private_key( gid, uid, enc_hex_key ) == -1) {
      sfs_debug( "sfs_adduser", "sfs_write_group_private_key error" );
      return 1;
    }
  }

// Encrypt the group private key for root 
  DE
    len = strlen( hex_key ) / 2;
    if(enc_bit_key){
      free(enc_bit_key);
      enc_bit_key = NULL;
    }
    enc_bit_key = sfs_asym_encrypt( root_pubkey, bit_key, &len );
    if (!enc_bit_key) {
      sfs_debug( "sfs_adduser", "sfs_asym_encrypt error" );
      return 1;
    }

    DE
    if(enc_hex_key){
      free(enc_hex_key);
      enc_hex_key = NULL;
    }
    enc_hex_key = bit2hex( enc_bit_key, len );
    if (!enc_hex_key) {
      sfs_debug( "sfs_adduser", "bit2hex error" );
      return 1;
    }

  DE
  // debug = 36

      if (sfs_write_group_private_key( gid, 0, enc_hex_key ) == -1) {
        sfs_debug( "sfs_adduser", "sfs_write_group_private_key error" );
        return 1;
      }
    }

/*
 * Generate all's public and private key and write them to appropriate files
 *
 */
  
DE
  // if key for everyone already exists
  all_ekey = sfs_read_all_private_key( 0 );
  if (all_ekey) {
DE
    len = strlen( all_ekey ) / 2;
DE
    all_ekey_bin = hex2bit( all_ekey, 0 ); 
    if(!all_ekey_bin) {
      sfs_debug("sfs_adduser","hex2bit error");
      return 1;
    }
DE
    all_dkey_bin = sfs_asym_decrypt( root_privkey, all_ekey_bin, &len );
    if(!all_dkey_bin) {
      sfs_debug("sfs_adduser","sfs_asym_decrypt error");
      return 1;
    }
    
DE
// sfs_debug( "login", "all_dkey: %s", bit2hex( all_dkey_bin, len ) );
 
    if(all_ekey_bin) {
      free(all_ekey_bin);
      all_ekey_bin = 0;
    }
    
    all_ekey_bin = sfs_asym_encrypt( &user_pubkey, all_dkey_bin, &len );
    if(!all_ekey_bin) {
      sfs_debug("sfs_adduser","sfs_asym_encrypt error");
      return 1;
    }
DE
    all_ekey = bit2hex( all_ekey_bin, len );
    if(!all_ekey) {
      sfs_debug("sfs_adduser","bit2bit error");
      return 1;
    }
DE
    ret = sfs_write_all_private_key( uid, all_ekey );
    if(ret == -1) {
      sfs_debug("sfs_adduser","sfs_write_all_private_key error");
      return 1;
    }
DE
  }
  // Keys for all not yet generated :-(
  else {
    
  DE
    // generate a pair of new asymetric keys
    sfs_asym_generate_key( &pubkey, &privkey );
    
  DE
    // publish public key
    if(hex_key) {
      free(hex_key);
      hex_key=NULL;
    }
    hex_key = sfs_asym_serialize_key( &pubkey );

    if(!hex_key) {
      sfs_debug("sfs_adduser","sfs_asym_serialize_key error");
      return 1;
    }

    ret = sfs_write_all_public_key( hex_key );
    if(ret == -1) {
      sfs_debug("sfs_adduser","sfs_write_all_public_key error");
      return 1;
    }
    
  DE
    // encrypt and store private key
    if(hex_key) {
      free(hex_key);
      hex_key=NULL;
    }

    hex_key = sfs_asym_serialize_key( &privkey );
    if(!hex_key ) {
      sfs_debug("sfs_adduser","sfs_asym_serialize_key error");
      return 1;
    }

  DE
    len = strlen( hex_key ) / 2;
    if(bit_key) {
      free(bit_key);
      bit_key=NULL;
    }

    bit_key = hex2bit( hex_key, 0 );
    if(!bit_key ) {
      sfs_debug("sfs_adduser","hex2bit error");
      return 1;
    }

  // For user
  DE
    if(enc_bit_key) {
      free(enc_bit_key);
      enc_bit_key=NULL;
    }
    enc_bit_key = sfs_asym_encrypt( &user_pubkey, bit_key, &len );

    if(!enc_bit_key ) {
      sfs_debug("sfs_adduser","sfs_asym_encrypt error");
      return 1;
    }

DE
    if(enc_hex_key) {
      free(enc_hex_key);
      enc_hex_key=NULL;
    }
    
    enc_hex_key = bit2hex( enc_bit_key, len );
    if(!enc_hex_key ) {
      sfs_debug("sfs_adduser","bit2hex error");
      return 1;
    }

  DE
    ret = sfs_write_all_private_key( uid, enc_hex_key );
    if(ret == -1) {
      sfs_debug("sfs_adduser","sfs_write_all_private_key error");
      return 1;
    }
    
  // For root if not already done

    if(uid != 0) {
    DE
      len = strlen( hex_key ) / 2;
      if(enc_bit_key) {
        free(enc_bit_key);
        enc_bit_key=NULL;
      }
      enc_bit_key = sfs_asym_encrypt( root_pubkey, bit_key, &len );
      if(!enc_bit_key ) {
        sfs_debug("sfs_adduser","sfs_asym_encrypt error");
        return 1;
      }

    DE
      if(enc_hex_key) {
        free(enc_hex_key);
        enc_hex_key=NULL;
      }
      enc_hex_key = bit2hex( enc_bit_key, len );
      if(!enc_hex_key ) {
        sfs_debug("sfs_adduser","bit2hex error");
        return 1;
      }

    DE
      ret = sfs_write_all_private_key( 0, enc_hex_key );
      if(ret == -1) {
        sfs_debug("sfs_adduser","sfs_write_all_private_key error");
        return 1;
      }
    }  
  DE
  }

  return 0;
}


//****************************************************************************
// main()
// ~~~~~~
// sfs_adduser main() function
//****************************************************************************
int
main()
{
  return sfs_adduser();
}

