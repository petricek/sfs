/*
 * sfs_secure.h
 *
 * Security funcitons prototypes used by SFS.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
 * Copyright 1998 Vaclav Petricek <petricek@mail.kolej.mff.cuni.cz>
 *
 */

#include "mrsa.h"
#include "blowfish.h"
#include "sfs_misc.h"

#ifndef _SFS_SECURE_H
#define _SFS_SECURE_H

#define RSA_BLOCK_SIZE (int)sizeof(NN) 
#define RSA_EF_BLOCK_SIZE (int)(sizeof(NN)/2) 

#ifdef BF_BLOCK_SIZE
#undef BF_BLOCK_SIZE
#endif
#define BF_BLOCK_SIZE (int)sizeof(bf_block) 

#define MAX_SYM_KEY_SIZE 20 

/*
 * Crypto functions
 * things without length are 0 terminated in hex notation
 *
 */

  // Encrypts data using blowfish
char *sfs_sym_encrypt(char* sym_key, char*what, int *length_what);
  // Decrypts data using blowfish
char *sfs_sym_decrypt(char* sym_key, char*what, int length_what);
  // Generates symetric key of specified length
char *sfs_sym_generate_key( int length );

  // Encrypts data using RSA
char *sfs_asym_encrypt(rsa_key * pub_key, char *what, int *length_what); 
  // Decrypts data using RSA
char *sfs_asym_decrypt(rsa_key * priv_key, char *what, int *length_what);
  // Generates a pair of asymetric keys
void  sfs_asym_generate_key(rsa_key *pub_key, rsa_key *priv_key);
  // Makes a printable hex string from rsa_key
char * sfs_asym_serialize_key(rsa_key * asym_key);
  // Makes a rsa_key from hex string
rsa_key * sfs_asym_parse_key(char * string_key);

#endif

