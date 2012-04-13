/* blowfish.c -- portable blowish encryption
 * 1994 Risto Paasivirta, paasivir@jyu.fi
 */

#include "blowfish.h"
#include "pixdigits.h"

/* #define LITTLE_ENDIAN if target is Intel etc.
 * default big endian, target Sparc, Motorola 68k etc.
 */

#ifdef LITTLE_ENDIAN
#define BR(x) (((x) >> 24) | (((x) >> 8) & 0xff00) | \
         (((x) << 8) & 0xff0000) | ((x) << 24))
/* Thanks for Jamie for correcting this error:
#define BR(x) (((x) >> 24) | (((x) >> 16) & 0xff00) | \
        (((x) << 16) & 0xff0000) | ((x) << 24))
*/
#else
#define BR(x) (x)
#endif

/* Calculate key schedule
 */

void
bf_set_key(uchar *key, int len, bf_key_schedule *ks)
{
  int i;
  ulong *p;
  bf_block bk = {0,0};

  p = ks->p;
  for (i = 0; i < 1042; i++)
    p[i] = pixdigits[i];
  if (len && key) {
    if (len > 56)
      len = 56;
    p = ks->p;
    for (i = 0; i < (BF_ROUNDS * 4 + 8); i += 4) {
      *p++ ^= ((ulong)key[i % len] << 24) |
              ((ulong)key[(i+1) % len] << 16) |
              ((ulong)key[(i+2) % len] << 8) |
              (ulong)key[(i+3) % len];
    }
  }
  p = ks->p;
  for (i = 0; i < (BF_ROUNDS / 2 + 514); i++) {
    bf_ecb_encrypt(&bk, &bk, ks, 1);
    *p++ = BR(bk.l);
    *p++ = BR(bk.r);
  }
}

/* Blowfish electronic code book mode
 */

void
bf_ecb_encrypt(bf_block *from, bf_block *to, bf_key_schedule *ks, int encrypt)
{
  int i;
  ulong l, r, t;

  l = BR(from->l); r = BR(from->r);
  if (encrypt) {
    for (i = 0; i < BF_ROUNDS; i++) {
      l ^= ks->p[i];
      r ^= ((ks->s1[(l >> 24) & 255] + ks->s2[(l >> 16) & 255]) ^
           ks->s3[(l >> 8) & 255]) + ks->s4[l & 255];
      t = l; l = r; r = t;
    }
    l ^= ks->p[BF_ROUNDS];
    r ^= ks->p[(BF_ROUNDS+1)];
  } else {
    for (i = (BF_ROUNDS+1); i > 1; i--) {
      l ^= ks->p[i];
      r ^= ((ks->s1[(l >> 24) & 255] + ks->s2[(l >> 16) & 255]) ^
           ks->s3[(l >> 8) & 255]) + ks->s4[l & 255];
      t = l; l = r; r = t;
    }
    l ^= ks->p[1];
    r ^= ks->p[0];
  }
  to->l = BR(r); to->r = BR(l);
}

/* Blowfish cipher block chaining mode
 */

int
bf_cbc_encrypt(bf_block *from, bf_block *to, int len,
  bf_key_schedule *ks, bf_block *ivec, int encrypt)
{
  int i;
  bf_block bk;

#ifdef LITTLE_ENDIAN
  ivec->l = BR(ivec->l); ivec->r = BR(ivec->r);
#endif
  if (encrypt) {
    for (i = 0; i < len; i += sizeof(bf_block)) {
      bk.l = from->l ^ ivec->l; bk.r = from->r ^ ivec->r;
      bf_ecb_encrypt(&bk, &bk, ks, 1);
      to->l = ivec->l = bk.l; to->r = ivec->r = bk.r;
      to++; from++;
    }
  } else {
    for (i = 0; i < len; i += sizeof(bf_block)) {
      bk.l = from->l; bk.r = from->r;
      bf_ecb_encrypt(&bk, &bk, ks, 0);
      bk.l ^= ivec->l; bk.r ^= ivec->r; 
      ivec->l = from->l; ivec->r = from->r;
      to->l = bk.l; to->r = bk.r;
      to++; from++;
    }
  }
#ifdef LITTLE_ENDIAN
  ivec->l = BR(ivec->l); ivec->r = BR(ivec->r);
#endif
  return i;
}

