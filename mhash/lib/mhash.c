/*
 *    Copyright (C) 1998 Nikos Mavroyanopoulos
 *    Copyright (C) 1999,2000 Sascha Schumman, Nikos Mavroyanopoulos
 *
 *    This library is free software; you can redistribute it and/or modify it 
 *    under the terms of the GNU Library General Public License as published 
 *    by the Free Software Foundation; either version 2 of the License, or 
 *    (at your option) any later version.
 *
 *    This library is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *    Library General Public License for more details.
 *
 *    You should have received a copy of the GNU Library General Public
 *    License along with this library; if not, write to the
 *    Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 *    Boston, MA 02111-1307, USA.
 */


/* $Id: mhash.c,v 1.6 2000/04/14 08:44:53 nmav Exp $ */

#include <stdlib.h>

#include "libdefs.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "mhash_int.h"
#include "mhash_crc32.h"
#include "mhash_haval.h"
#include "mhash_md5.h"
#include "mhash_sha1.h"
#include "mhash_tiger.h"
#include "mhash_ripemd.h"
#include "gosthash.h"

/* 19/03/2000 Changes for better thread handling --nikos */

#define MHASH_ENTRY(name, blksize, hash_pblock) \
	{ #name, name, blksize, hash_pblock }

struct mhash_hash_entry {
	char *name;
	hashid id;
	size_t blocksize;
	size_t hash_pblock;
};

static mhash_hash_entry algorithms[] = {
	MHASH_ENTRY(MHASH_CRC32, 4, 0),
	MHASH_ENTRY(MHASH_MD5, 16, 64),
	MHASH_ENTRY(MHASH_SHA1, 20, 64),
	MHASH_ENTRY(MHASH_HAVAL256, 32, 128),
	MHASH_ENTRY(MHASH_HAVAL128, 16, 128),
	MHASH_ENTRY(MHASH_HAVAL160, 20, 128),
	MHASH_ENTRY(MHASH_HAVAL192, 24, 128),
	MHASH_ENTRY(MHASH_HAVAL224, 28, 128),
	MHASH_ENTRY(MHASH_RIPEMD160, 20, 64),
	MHASH_ENTRY(MHASH_TIGER, 192 >> 3, 64),
	MHASH_ENTRY(MHASH_GOST, 32, 0),
	MHASH_ENTRY(MHASH_CRC32B, 4, 0),
	{0}
};

#define MHASH_LOOP(b) \
	mhash_hash_entry *p; \
	for(p = algorithms; p->name != NULL; p++) { b ; }

#define MHASH_ALG_LOOP(a) \
	MHASH_LOOP( if(p->id == type) { a; break; } )

size_t mhash_count(void)
{
	size_t count = 0;

	MHASH_LOOP(count++);

	return count;
}

size_t mhash_get_block_size(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->blocksize);
	return ret;
}

char *mhash_get_hash_name(hashid type)
{
	char *ret = NULL;

	/* avoid prefix */
	MHASH_ALG_LOOP(ret = strdup(p->name + sizeof("MHASH_") - 1));

	return ret;
}

MHASH mhash_init_int(const hashid type)
{
	MHASH ret;
	int i;

	ret = malloc(sizeof(MHASH_INSTANCE));
	ret->algorithm_given = type;

	switch (type) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		ret->state = malloc(sizeof(word32));
		clear_crc32((void *) ret->state);
		break;
	case MHASH_MD5:
		ret->state = malloc(sizeof(MD5_CTX));
		MD5Init((void *) ret->state);
		break;
	case MHASH_SHA1:
		ret->state = malloc(sizeof(SHA_CTX));
		sha_init((void *) ret->state);
		break;
	case MHASH_HAVAL256:
		ret->state = malloc(sizeof(havalContext));
		havalInit( (void *) ret->state, 3, 256);
		break;
	case MHASH_HAVAL224:
		ret->state = malloc(sizeof(havalContext));
		havalInit( (void *) ret->state, 3, 224);
		break;
	case MHASH_HAVAL192:
		ret->state = malloc(sizeof(havalContext));
		havalInit( (void *) ret->state, 3, 192);
		break;
	case MHASH_HAVAL160:
		ret->state = malloc(sizeof(havalContext));
		havalInit( (void *) ret->state, 3, 160);
		break;
	case MHASH_HAVAL128:
		ret->state = malloc(sizeof(havalContext));
		havalInit( (void *) ret->state, 3, 128);
		break;
	case MHASH_RIPEMD160:
		ret->state = malloc(sizeof(RIPEMD_CTX));
		ripemd_init((void *) ret->state);
		break;
	case MHASH_TIGER:
		ret->state = malloc(3 * sizeof(word64));
		break;
	case MHASH_GOST:
		ret->state = malloc(sizeof(GostHashCtx));
		gosthash_reset((void *) ret->state);
		break;
	default:
		ret = MHASH_FAILED;
		break;
	}
	
	return ret;
}

#define MIX32(a) \
	(((unsigned long)((unsigned char *)(a))[0]) | \
	(((unsigned long)((unsigned char *)(a))[1]) << 8)| \
	(((unsigned long)((unsigned char *)(a))[2]) << 16)| \
	(((unsigned long)((unsigned char *)(a))[3]) << 24))


#ifdef WORDS_BIGENDIAN
void mhash_32bit_conversion(word32 * ptr, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		ptr[i] = MIX32(&ptr[i]);
	}
}
#else
#define mhash_32bit_conversion(a,b)
#endif

/* plaintext should be a multiply of the algorithm's block size */

int mhash(MHASH thread, const void *plaintext, size_t size)
{

	switch (thread->algorithm_given) {
	case MHASH_CRC32:
		crc32((void *) thread->state, plaintext, size);
		break;
	case MHASH_CRC32B:
		crc32b((void *) thread->state, plaintext, size);
		break;
	case MHASH_MD5:
		MD5Update((void *) thread->state, plaintext, size);
		break;
	case MHASH_SHA1:
		sha_update((void *) thread->state, (void *) plaintext,
			   size);
		break;
	case MHASH_HAVAL256:
	case MHASH_HAVAL224:
	case MHASH_HAVAL192:
	case MHASH_HAVAL160:
	case MHASH_HAVAL128:
		havalUpdate((void *) thread->state, plaintext, size);
		break;
	case MHASH_RIPEMD160:
		ripemd_update((void *) thread->state, (void *) plaintext,
			      size);
		break;
	case MHASH_TIGER:
		tiger(plaintext, size, (void *) thread->state);
		break;
	case MHASH_GOST:
		gosthash_update((void *) thread->state, plaintext, size);
		break;
	}

	return 0;
}


void *mhash_end(MHASH thread)
{
	void *digest;
	void *rtmp = NULL;

	switch (thread->algorithm_given) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		rtmp = get_crc32((void *) thread->state);
		break;
	case MHASH_MD5:
		digest =
		    malloc(mhash_get_block_size(thread->algorithm_given));
		MD5Final(digest, (void *) thread->state);
		rtmp=digest;
		break;
	case MHASH_SHA1:
		sha_final((void *) thread->state);
		digest = malloc(SHA_DIGESTSIZE);
		sha_digest((void *) thread->state, digest);
		rtmp = digest;
		break;
	case MHASH_HAVAL256:
	case MHASH_HAVAL224:
	case MHASH_HAVAL192:
	case MHASH_HAVAL160:
	case MHASH_HAVAL128:
		digest =
		    malloc(mhash_get_block_size(thread->algorithm_given));
		havalFinal((void *) thread->state, digest);
		rtmp = digest;
		break;
	case MHASH_RIPEMD160:
		ripemd_final((void *) thread->state);
		digest = malloc(RIPEMD_DIGESTSIZE);
		ripemd_digest((void *) thread->state, digest);
		rtmp = digest;
		break;
	case MHASH_TIGER:
		digest = malloc(192 >> 3);
		memcpy(digest, (void *) thread->state, 192 >> 3);
		mhash_32bit_conversion(digest, 192 >> 5);
		rtmp = digest;
		break;
	case MHASH_GOST:
		digest = malloc(32);
		gosthash_final((void *) thread->state, digest);
		rtmp = digest;
		break;
	}

	free(thread->state);
	free(thread);

	return rtmp;
}

MHASH mhash_init(const hashid type)
{
	static int gost_init, crc32b_init;
	MHASH ret = MHASH_FAILED;

	if (type == MHASH_GOST && !gost_init) {
		gosthash_init();
		gost_init++;
	}

	if (type == MHASH_CRC32B && !crc32b_init) {
		crc32b_init++;
		crc32bgen();
	}

	ret = mhash_init_int(type);

	return ret;
}

/* HMAC functions */

size_t mhash_get_hash_pblock(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->hash_pblock);
	return ret;
}

void *mhash_hmac_end(MHASH thread)
{
	void *digest;
	unsigned char *opad;
	MHASH tmptd;
	void *return_val;
	int i;

	opad = malloc(thread->hmac_block);

	for (i = 0; i < thread->hmac_key_size; i++) {
		opad[i] = (0x5C) ^ thread->hmac_key[i];
	}
	for (; i < thread->hmac_block; i++) {
		opad[i] = (0x5C);
	}

	tmptd = mhash_init(thread->algorithm_given);
	mhash(tmptd, opad, thread->hmac_block);

	switch (thread->algorithm_given) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		return_val = get_crc32((void *) thread->state);
		break;
	case MHASH_MD5:
		digest =
		    malloc(mhash_get_block_size(thread->algorithm_given));
		MD5Final(digest, (void *) thread->state);
		return_val = digest;
		break;
	case MHASH_SHA1:
		digest = malloc(SHA_DIGESTSIZE);
		sha_final((void *) thread->state);
		sha_digest((void *) thread->state, digest);
		return_val = digest;
		break;
	case MHASH_HAVAL256:
	case MHASH_HAVAL224:
	case MHASH_HAVAL192:
	case MHASH_HAVAL160:
	case MHASH_HAVAL128:
		digest =
		    malloc(mhash_get_block_size(thread->algorithm_given));
		havalFinal((void *) thread->state, digest);
		return_val = digest;
		break;
	case MHASH_RIPEMD160:
		digest = malloc(RIPEMD_DIGESTSIZE);
		ripemd_final((void *) thread->state);
		ripemd_digest((void *) thread->state, digest);
		return_val = digest;
		break;
	case MHASH_TIGER:
		digest = malloc(192 >> 3);
		memcpy(digest, (void *) thread->state, 192 >> 3);
		return_val = digest;
		break;
	case MHASH_GOST:
		digest = malloc(32);
		gosthash_final((void *) thread->state, digest);
		return_val = digest;
		break;
	}

	mhash(tmptd, return_val,
	      mhash_get_block_size(thread->algorithm_given));

	free(thread->state);
	mhash_bzero( thread->hmac_key, thread->hmac_key_size);
	free(thread->hmac_key);
	free(thread);

	return mhash_end(tmptd);
}

MHASH mhash_hmac_init(const hashid type, void *key, int keysize, int block)
{
	static int gost_init, crc32b_init;
	MHASH ret = MHASH_FAILED;
	MHASH tmptd;
	unsigned char *tmp;
	unsigned char *ipad;
	int i;

	if (block == 0) {
		block = 64;	/* the default for ripemd,md5,sha-1 */
	}

	if (type == MHASH_GOST && !gost_init) {
		gost_init++;
		gosthash_init();
	}

	if (type == MHASH_CRC32B && !crc32b_init) {
		crc32b_init++;
		crc32bgen();
	}


		ret = mhash_init_int(type);

		if (ret != MHASH_FAILED) {
			/* Initial hmac calculations */
			ret->hmac_block = block;

			ipad = malloc(ret->hmac_block);

			if (keysize > ret->hmac_block) {
				tmptd = mhash_init(type);
				mhash(tmptd, key, keysize);
				ret->hmac_key_size =
				    mhash_get_block_size(type);
				ret->hmac_key = mhash_end(tmptd);
			} else {
				ret->hmac_key = calloc(1, ret->hmac_block);
				memmove(ret->hmac_key, key, keysize);
				ret->hmac_key_size = ret->hmac_block;
			}

			/* IPAD */

			for (i = 0; i < ret->hmac_key_size; i++) {
				ipad[i] = (0x36) ^ ret->hmac_key[i];
			}
			for (;i<ret->hmac_block;i++) {
				ipad[i] = (0x36);
			}

			mhash(ret, ipad, ret->hmac_block);
		}



	return ret;
}

void mhash_free(void * ptr) {
	free(ptr);
}
