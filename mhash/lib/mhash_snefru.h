/* mhash_snefru.h */

/* Snefru is a cryptographic hash function invented by Ralph Merkle
 * which supports 128-bit and 256-bit output. It was named after the
 * Egyptian Pharaoh Sneferu, continuing the tradition of the Khufu and
 * Khafre block ciphers.
 *
 * Snefru is a public-domain one-way hash function. For more information see
 * http://www.funet.fi/pub/crypt/mirrors/idea.sec.dsi.unimi.it/rpub.cl.msu.edu/
 *   crypt/docs/merkle-khufu-khafre-snefru.txt.gz
 *
 * This code was written by B. Poettering in 2004 for the mhash library. It
 * is in the public domain. 
 */

#ifndef MHASH_SNEFRU_H_INCLUDED
#define MHASH_SNEFRU_H_INCLUDED

#define SNEFRU128_DATA_SIZE 48
#define SNEFRU128_DIGEST_SIZE 16
#define SNEFRU128_DIGEST_LEN (SNEFRU128_DIGEST_SIZE / 4)

#define SNEFRU256_DATA_SIZE 32
#define SNEFRU256_DIGEST_SIZE 32
#define SNEFRU256_DIGEST_LEN (SNEFRU256_DIGEST_SIZE / 4)

#define SNEFRU_BLOCK_SIZE  64
#define SNEFRU_BLOCK_LEN (SNEFRU_BLOCK_SIZE / 4)

typedef struct snefru_ctx
{
  byte buffer[SNEFRU128_DATA_SIZE];	   /* buffer of data to hash */
  word64 hashlen;                          /* number of hashed bits */
  int index;		                   /* index to buffer */
  word32 hash[SNEFRU_BLOCK_LEN];           /* the hashing state */
} SNEFRU_CTX;

void
snefru_init(struct snefru_ctx *ctx);

void
snefru128_update(struct snefru_ctx *ctx, const byte *data, unsigned length);

void
snefru256_update(struct snefru_ctx *ctx, const byte *data, unsigned length);

void
snefru128_final(struct snefru_ctx *ctx);

void
snefru256_final(struct snefru_ctx *ctx);

void
snefru128_digest(const struct snefru_ctx *ctx, byte *digest);

void
snefru256_digest(const struct snefru_ctx *ctx, byte *digest);


#endif   /* MHASH_SNEFRU_H_INCLUDED */
