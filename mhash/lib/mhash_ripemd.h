#ifndef MHASH_RIPEMD_H
#define MHASH_RIPEMD_H

#include <libdefs.h>

#define ripemd_init 		mhash_ripemd_init
#define ripemd_update 		mhash_ripemd_update
#define ripemd_final		mhash_ripemd_final
#define ripemd_digest		mhash_ripemd_digest
#define ripemd_copy			mhash_ripemd_copy

/* The RIPEMD block size and message digest sizes, in bytes */

#define RIPEMD_DATASIZE    64
#define RIPEMD_DATALEN     16
#define RIPEMD_DIGESTSIZE  20
#define RIPEMD_DIGESTLEN    5
/* The structure for storing RIPEMD info */

typedef struct ripemd_ctx {
  word32 digest[RIPEMD_DIGESTLEN];  /* Message digest */
  word32 count_l, count_h;       /* 64-bit block count */
  word8 block[RIPEMD_DATASIZE];     /* RIPEMD data buffer */
  int index;                             /* index into buffer */
} RIPEMD_CTX;

void ripemd_init(struct ripemd_ctx *ctx);
void ripemd_update(struct ripemd_ctx *ctx, word8 *buffer, word32 len);
void ripemd_final(struct ripemd_ctx *ctx);
void ripemd_digest(struct ripemd_ctx *ctx, word8 *s);
void ripemd_copy(struct ripemd_ctx *dest, struct ripemd_ctx *src);

#endif
