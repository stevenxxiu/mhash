#ifndef MHASH_TIGER_H
#define MHASH_TIGER_H

#include "libdefs.h"

#define h0init 0x89ABCDEF;
#define h1init 0x01234567;
#define h2init 0x76543210;
#define h3init 0xFEDCBA98;
#define h4init 0xC3B2E187;
#define h5init 0xF096A5B4;

#define TIGER_DATALEN 16
#define TIGER_DIGESTLEN 6
#define TIGER_DIGESTSIZE 24
#define TIGER_DATASIZE 64

typedef struct tiger_ctx {
  word32 digest[TIGER_DIGESTLEN];  /* Message digest */ 
  word32 count_l, count_h;	 /* 64-bit block count */
  word8 block[TIGER_DATASIZE];     /* RIPEMD data buffer */  
  int index;                             /* index into buffer */
} TIGER_CTX;


void tiger_digest(struct tiger_ctx *ctx, word8 * s);
void tiger_final(struct tiger_ctx *ctx);
void tiger_update(struct tiger_ctx *ctx, word8 * buffer, word32 len);
void tiger_init(struct tiger_ctx *ctx);

#endif
