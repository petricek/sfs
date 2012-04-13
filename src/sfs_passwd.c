/*
 * sfs_passwd.c
 *
 * Change password to the SFS subsystem.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 *
 */

#include <string.h>
#include <unistd.h>

#include "sfs.h"
#include "sfs_misc.h"
#include "sfs_debug.h"
#include "sfs_secure.h"


//----------------------------------------------------------------------------
// sfs_passwd()
// ~~~~~~~~~~~~
// Change password to SFS subsystem
// Status: almost finished
//----------------------------------------------------------------------------
int
sfs_passwd( void )
{
  char *old_pass, *new_pass;
  char *dkey_bin, *ekey, *ekey_bin;
  uid_t uid;
  int len;

  uid = getuid();
  
  old_pass = strdup( getpass( SFS_PASSWD_OLD ) );
  if (!old_pass) {
    sfs_debug( "sfs_passwd", "password is empty" );
    return 1;
  }

  new_pass = strdup( getpass( SFS_PASSWD_NEW ) );
  if (!new_pass) {
    sfs_debug( "sfs_passwd", "password is empty" );
    return 1;
  }
  
  ekey = sfs_read_user_private_key( uid );
  if(ekey == NULL)
  {
    sfs_debug("sfs_passwd","error reading user private key");
    return 1;
  }
  len = strlen( ekey )/2;
  ekey_bin = hex2bit( ekey, 0 );
  dkey_bin = sfs_sym_decrypt( old_pass, ekey_bin, len );
  if(dkey_bin == NULL)
  {
    sfs_debug("sfs_passwd","error decrypting user private key");
    return 1;
  }
  ekey_bin = sfs_sym_encrypt( new_pass, dkey_bin, &len );
  if(ekey_bin == NULL)
  {
    sfs_debug("sfs_passwd","error reencrypting user private key");
    return 1;
  }
  ekey = bit2hex( ekey_bin, len );
  if(ekey == NULL)
  {
    sfs_debug("sfs_passwd","error converting encrypted private key to hex");
    return 1;
  }
  sfs_write_user_private_key( uid, ekey );
  if(ekey == NULL)
  {
    sfs_debug("sfs_passwd","error writing encrypted user private key");
    return 1;
  }
  
  return 0;
}


//----------------------------------------------------------------------------
// main()
// ~~~~~~
// sfs_passwd main() function
// Status: NOT finished
//----------------------------------------------------------------------------
int
main()
{
  return sfs_passwd();
}

