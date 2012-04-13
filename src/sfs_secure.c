/*
 * sfs_secure.c
 *
 * Security funcitons used by SFS.
 *
 * Copyright 1998 Michal Svec <rebel@atrey.karlin.mff.cuni.cz>
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
#include <sys/stat.h>
#include <sys/types.h>

#define _SFS_DEBUG_DAEMON

#include "sfs.h"
#include "sfs_debug.h"
#include "sfs_secure.h"


// *********************************************************************** 
// sfs_sym_encrypt()
// ~~~~~~~~~~~~~~~~~
// Produces block of data rounded up to next multiple of BF_BLOCK_SIZE 
// *********************************************************************** 
char*
sfs_sym_encrypt( char* sym_key, char *what, int *length_what )
{
  char *temp = (char*)malloc((((*length_what)/BF_BLOCK_SIZE)+1)*BF_BLOCK_SIZE);
  bf_block block;   
  bf_key_schedule ks;
  int i = 0, k = 0;

  // prepare key
  bf_set_key((unsigned char *)sym_key, strlen(sym_key), &ks);
  
  while(i < ((*length_what)-BF_BLOCK_SIZE+1)){

    for(k=0;k<BF_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = what[i+k];

    bf_ecb_encrypt(&block, &block, &ks, 1);

    for(k=0;k<BF_BLOCK_SIZE;k++)
      temp[i+k] = ((unsigned char*)&block)[k];

    i += BF_BLOCK_SIZE;
  }

  if(i<(*length_what))
  {
    for(k=0;k+i<(*length_what);k++)
      ((unsigned char*)&block)[k] = what[i+k];
    for(;k<BF_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = 0;

    bf_ecb_encrypt(&block, &block, &ks, 1);

    for(k=0;k<BF_BLOCK_SIZE;k++)
      temp[i+k] = ((unsigned char*)&block)[k];
  }

  *length_what = i+k;
  
  return temp;
}


// *********************************************************************** 
// sfs_sym_decrypt()
// ~~~~~~~~~~~~~~~~~
// If length_what is not a multiple of 8 it ignores the end * uses blowfish
// Preserves length of data
// *********************************************************************** 
char*
sfs_sym_decrypt( char *sym_key, char *what, int length_what )
{
  int i = 0, k = 0;
  char * temp = (char *)malloc(length_what);
  bf_block block;   
  bf_key_schedule ks;

  // prepare key
  bf_set_key((unsigned char *)sym_key, strlen(sym_key), &ks);
  
  while(i <= length_what-BF_BLOCK_SIZE){
    
    for(k=0;k<BF_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = what[i+k];

    bf_ecb_encrypt(&block, &block, &ks, 0);

    for(k=0;k<BF_BLOCK_SIZE;k++)
      temp[i+k] = ((unsigned char*)&block)[k];

    i += BF_BLOCK_SIZE;
  }

  // length_what = i;
  
  return temp;
}


// *********************************************************************** 
// sfs_sym_generate_key()
// ~~~~~~~~~~~~~~~~~~~~~~
// Generates a random symetric key
// *********************************************************************** 
char*
sfs_sym_generate_key( int size )
{
  int i=0;
  static init = 0;
  char *array_key, *sym_key;
  sym_key = (char*)malloc(size*2+1);
  array_key = (char *)malloc(size);
  if(!init)
  {
    srand(time(0));
    init = 1;
  }
  while (i<size) {
    array_key[i] = (char)rand();
    i++;
  }
  sym_key = bit2hex(array_key, size);
  free(array_key);
  return sym_key; 
}


// *********************************************************************** 
// sfs_asym_encrypt()
// ~~~~~~~~~~~~~~~~~~
// Encrypts data in what using pub_key * uses RSA algorithm
// *********************************************************************** 
char*
sfs_asym_encrypt( rsa_key * pub_key, char *what, int *length_what )
{
  // Has to alllocate greater space than input, because in this encryption
  // just RSA_EF_BLOCK_SIZE can be effectively used
  uchar* temp = (uchar*)malloc(((*length_what / RSA_EF_BLOCK_SIZE) + 1) * RSA_BLOCK_SIZE);
  uint ratio = (RSA_BLOCK_SIZE/RSA_EF_BLOCK_SIZE);
  int i=0,k=0;
  NN block;

//  sfs_debug("sfs_asym_encrypt","len:%d\nkey:%s\nwhat:%s",*length_what,sfs_asym_serialize_key(pub_key),what);
  i=0;
  while(i <= ((*length_what) - RSA_EF_BLOCK_SIZE))
  {
    for(k=0;k<RSA_EF_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = ((unsigned char *)what)[i+k];
    for(;k<RSA_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = 0;

    rsa_enc(block, pub_key);

    for(k=0;k<RSA_BLOCK_SIZE;k++)
      temp[ratio * i+k] = ((unsigned char*)&block)[k];

    i += RSA_EF_BLOCK_SIZE;
  }

  // Encodes the rest that is not a multiple of RSA_EF_BLOCK_SIZE
  if((*length_what) > i)
  {
    for(k=0;k<(*length_what) - i;k++)
      ((unsigned char*)&block)[k] = ((unsigned char *)what)[i+k];
    for(;k<RSA_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = 0;

    rsa_enc(block, pub_key);
    // rsa_dec(block, pub_key);
    // em(block, pub_key->d, pub_key->pq);

    for(k=0;k< RSA_BLOCK_SIZE;k++)
      temp[ratio * i+k] = ((unsigned char*)&block)[k];
  }

  *length_what = ((*length_what / RSA_EF_BLOCK_SIZE) + 1) * RSA_BLOCK_SIZE;

  return (char *)temp;
}


// *********************************************************************** 
// sfs_asym_decrypt()
// ~~~~~~~~~~~~~~~~~~
// Decrypts data in what using pub_key * uses RSA algorithm
// ROunds the size of what down to a multiple of RSA_BLOCK_SIZE
// sfs_sym_encrypt produces chunks of data with length being a multiple
// of RSA_BLOCK_SIZE so this should not be an issue
// *********************************************************************** 
char*
sfs_asym_decrypt( rsa_key * priv_key, char *what, int *length_what )
{

  uint ratio = (RSA_BLOCK_SIZE/RSA_EF_BLOCK_SIZE);
  NN block;
  uint i =0,k=0;
  uchar* temp = (uchar*)malloc(((*length_what) / RSA_BLOCK_SIZE)  * RSA_EF_BLOCK_SIZE);
  if(!temp)
  {
    sfs_debug("sfs_asym_decrypt","memory error");
    return NULL;
  }
  if(!(((*length_what) % RSA_BLOCK_SIZE) == 0))
  {
    free(temp);
    sfs_debug("sfs_asym_decrypt","data not a multiple of BLOCK SIZE: %d", RSA_BLOCK_SIZE);
    return NULL;
  }

  i=0;
  while(i<= (uint)*length_what - RSA_BLOCK_SIZE)
  {

    for(k=0;k<RSA_BLOCK_SIZE;k++)
      ((unsigned char*)&block)[k] = ((unsigned char *)what)[i+k];

    rsa_dec(block, priv_key);

    for(k=0;k<RSA_EF_BLOCK_SIZE;k++)
      temp[(i/ratio) +k] = ((unsigned char*)&block)[k];

    i += RSA_BLOCK_SIZE;
  }
  *length_what = (*length_what / RSA_BLOCK_SIZE)  * RSA_EF_BLOCK_SIZE;
  return (char *)temp;
}


// *********************************************************************** 
// sfs_asym_generate_key()
// ~~~~~~~~~~~~~~~~~~~~~~~
// Generates a pair of asymetric keys * RSA algorithm
// *********************************************************************** 
void
sfs_asym_generate_key( rsa_key * pub_key, rsa_key * priv_key )
{
  int i = 0,size = 0;
  float real;
  static int init =0;
  if(!init)
  {
    srand(time(0));
    init = 1;
  }
  real = rand();
  real /= RAND_MAX; 
  size = 80 + real*20; 
  randomize(pub_key->p,size); 
  randomize(pub_key->q,size); 
 
  rsa_gen(pub_key);

  // Copy priv_key to pub_key
  priv_key->b = pub_key->b;
  for(i=0;i<NSIZE;i++)
  {
    priv_key->p[i]  = pub_key->p[i];
    priv_key->q[i]  = pub_key->q[i];
    priv_key->pq[i] = pub_key->pq[i];
    priv_key->e[i]  = pub_key->e[i];
    priv_key->d[i]  = pub_key->d[i];
    priv_key->dp[i] = pub_key->dp[i];
    priv_key->dq[i] = pub_key->dq[i];
    priv_key->qp[i] = pub_key->qp[i];
  }
  // Clears parts of keys that should be confidential 
 // Public
  // cl(pub_key->dp);
  // cl(pub_key->dq);
  // cl(pub_key->dp);
  // cl(pub_key->p);
  // cl(pub_key->q);
  // cl(pub_key->qp);
  // cl(pub_key->d);
 // Private
  // cl(priv_key->dp);
  // cl(priv_key->dq);
  // cl(priv_key->qp);
  // cl(priv_key->e);
}


//****************************************************************************
// sfs_asym_parse_key()
// ~~~~~~~~~~~~~~~~~~~~
// Parses string and creates an asymetric key
//****************************************************************************
rsa_key*
sfs_asym_parse_key( char * key_string )
{
  uint i = 0;
  char * bit_key = NULL;
  rsa_key * temp_key = (rsa_key *)malloc(sizeof(rsa_key));
  
  uint len = strlen(key_string);
  if((len/2) < sizeof(rsa_key))
  {
    free(temp_key);
    sfs_debug("sfs_asym_parse_key","hex key too short to fill rsa_key.");
    return NULL;
  }

  bit_key = hex2bit(key_string,len);
  len = len / 2;

  for(i=0;i<sizeof(rsa_key);i++)
    ((char *)temp_key)[i] = bit_key[i];

  free(bit_key);
  return temp_key;

}


//****************************************************************************
// sfs_asym_serialize_key()
// ~~~~~~~~~~~~~~~~~~~~~~~~
// Creates a string containing asymetric key 
//****************************************************************************
char*
sfs_asym_serialize_key( rsa_key * asym_key )
{

  char * hex_string = NULL;
  char * temp_string; 

  temp_string = ((char *)asym_key);

  hex_string = bit2hex(temp_string,sizeof(rsa_key));

  return hex_string;

}

