/* blowfish.h
 * 1994 by Risto Paasivirta, paasivir@jyu.fi
 */

#ifndef _BLOWFISH_H
#define _BLOWFISH_H 1

#include <sys/types.h>

typedef unsigned char uchar;

#define BF_ROUNDS 16

typedef struct bf_key_schedule {
  ulong p[BF_ROUNDS+2];
  ulong s1[256];
  ulong s2[256];
  ulong s3[256];
  ulong s4[256];
} bf_key_schedule;

typedef struct bf_block {
  ulong l,r;
} bf_block;

void bf_set_key(uchar *key, int len, bf_key_schedule *ks);
void bf_ecb_encrypt(bf_block *from, bf_block *to, bf_key_schedule *ks,
  int encrypt);
int bf_cbc_encrypt(bf_block *input, bf_block *output,
  int len, bf_key_schedule *ks, bf_block *ivec, int encrypt);

#endif /* _BLOWFISH_H */

