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


/* $Id: mhash.c,v 1.12 2000/12/15 12:11:47 nmav Exp $ */

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

WIN32DLL_DEFINE size_t mhash_count(void)
{
	size_t count = 0;

	MHASH_LOOP(count++);

	return count;
}

WIN32DLL_DEFINE size_t mhash_get_block_size(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->blocksize);
	return ret;
}

#ifdef WIN32
/* function created in order for mhash to compile under WIN32 */
char *mystrdup(char *str)
{
	char *ret;
	ret = malloc(strlen(str) + 1);
	strcpy(ret, str);

	return ret;

}
#endif

WIN32DLL_DEFINE hashid mhash_get_mhash_algo( MHASH tmp) {
	return tmp->algorithm_given;
}

WIN32DLL_DEFINE char *mhash_get_hash_name(hashid type)
{
	char *ret = NULL;

	/* avoid prefix */
	MHASH_ALG_LOOP(ret = mystrdup(p->name + sizeof("MHASH_") - 1));
	return ret;
}

MHASH mhash_cp(MHASH from) {
MHASH ret;

	ret = malloc(sizeof(MHASH_INSTANCE));
	memcpy(ret, from, sizeof(MHASH_INSTANCE));
	
	/* copy the internal state also */
	ret->state=malloc(ret->state_size);
	memcpy( ret->state, from->state, ret->state_size);
	
	/* copy the key in case of hmac*/
	if (ret->hmac_key_size!=0) {
		ret->hmac_key=malloc(ret->hmac_key_size);
		memcpy(ret->hmac_key, from->hmac_key, ret->hmac_key_size);
	}
	return ret;

}
MHASH mhash_init_int(const hashid type)
{
	MHASH ret;
	int i;

	ret = malloc(sizeof(MHASH_INSTANCE));
	ret->algorithm_given = type;
	ret->hmac_key = NULL;
	ret->state = NULL;
	ret->hmac_key_size = 0;
	
	switch (type) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		ret->state_size = sizeof(word32);
		ret->state = malloc(ret->state_size);
		clear_crc32((void *) ret->state);
		break;
	case MHASH_MD5:
		ret->state_size = sizeof(MD5_CTX);
		ret->state = malloc(ret->state_size);
		MD5Init((void *) ret->state);
		break;
	case MHASH_SHA1:
		ret->state_size = sizeof(SHA_CTX);
		ret->state = malloc(ret->state_size);
		sha_init((void *) ret->state);
		break;
	case MHASH_HAVAL256:
		ret->state_size = sizeof(havalContext);
		ret->state = malloc(ret->state_size);
		havalInit((void *) ret->state, 3, 256);
		break;
	case MHASH_HAVAL224:
		ret->state_size = sizeof(havalContext);
		ret->state = malloc(ret->state_size);
		havalInit((void *) ret->state, 3, 224);
		break;
	case MHASH_HAVAL192:
		ret->state_size = sizeof(havalContext);
		ret->state = malloc(ret->state_size);
		havalInit((void *) ret->state, 3, 192);
		break;
	case MHASH_HAVAL160:
		ret->state_size = sizeof(havalContext);
		ret->state = malloc(ret->state_size);
		havalInit((void *) ret->state, 3, 160);
		break;
	case MHASH_HAVAL128:
		ret->state_size = sizeof(havalContext);
		ret->state = malloc(ret->state_size);
		havalInit((void *) ret->state, 3, 128);
		break;
	case MHASH_RIPEMD160:
		ret->state_size = sizeof(RIPEMD_CTX);
		ret->state = malloc(ret->state_size);
		ripemd_init((void *) ret->state);
		break;
	case MHASH_TIGER:
		ret->state_size = 3 * sizeof(word64);
		ret->state = malloc(ret->state_size);
		break;
	case MHASH_GOST:
		ret->state_size = sizeof(GostHashCtx);
		ret->state = malloc(ret->state_size);
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

WIN32DLL_DEFINE
    void *mhash_end_m(MHASH thread, void *(*hash_malloc) (size_t))
{
	void *digest;
	void *rtmp = NULL;

	switch (thread->algorithm_given) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		rtmp = hash_malloc(sizeof(word32));
		get_crc32(rtmp, (void *) thread->state);
		break;
	case MHASH_MD5:
		digest =
		    hash_malloc(mhash_get_block_size
				(thread->algorithm_given));
		MD5Final(digest, (void *) thread->state);
		rtmp = digest;
		break;
	case MHASH_SHA1:
		sha_final((void *) thread->state);
		digest = hash_malloc(SHA_DIGESTSIZE);
		sha_digest((void *) thread->state, digest);
		rtmp = digest;
		break;
	case MHASH_HAVAL256:
	case MHASH_HAVAL224:
	case MHASH_HAVAL192:
	case MHASH_HAVAL160:
	case MHASH_HAVAL128:
		digest =
		    hash_malloc(mhash_get_block_size
				(thread->algorithm_given));
		havalFinal((void *) thread->state, digest);
		rtmp = digest;
		break;
	case MHASH_RIPEMD160:
		ripemd_final((void *) thread->state);
		digest = hash_malloc(RIPEMD_DIGESTSIZE);
		ripemd_digest((void *) thread->state, digest);
		rtmp = digest;
		break;
	case MHASH_TIGER:
		digest = hash_malloc(192 >> 3);
		memcpy(digest, (void *) thread->state, 192 >> 3);
		mhash_32bit_conversion(digest, 192 >> 5);
		rtmp = digest;
		break;
	case MHASH_GOST:
		digest = hash_malloc(32);
		gosthash_final((void *) thread->state, digest);
		rtmp = digest;
		break;
	}

	if (NULL != thread->state) {
		free(thread->state);
	}
	free(thread);

	return rtmp;
}

WIN32DLL_DEFINE void *mhash_end(MHASH thread)
{
	return mhash_end_m(thread, malloc);
}


WIN32DLL_DEFINE MHASH mhash_init(const hashid type)
{
	MHASH ret = MHASH_FAILED;

	ret = mhash_init_int(type);

	return ret;
}

/* HMAC functions */

WIN32DLL_DEFINE size_t mhash_get_hash_pblock(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->hash_pblock);
	return ret;
}


WIN32DLL_DEFINE
    void *mhash_hmac_end_m(MHASH thread, void *(*hash_malloc) (size_t))
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
		digest = hash_malloc(sizeof(word32));
		get_crc32(digest, (void *) thread->state);
		return_val = digest;
		break;
	case MHASH_MD5:
		digest =
		    hash_malloc(mhash_get_block_size
				(thread->algorithm_given));
		MD5Final(digest, (void *) thread->state);
		return_val = digest;
		break;
	case MHASH_SHA1:
		digest = hash_malloc(SHA_DIGESTSIZE);
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
		    hash_malloc(mhash_get_block_size
				(thread->algorithm_given));
		havalFinal((void *) thread->state, digest);
		return_val = digest;
		break;
	case MHASH_RIPEMD160:
		digest = hash_malloc(RIPEMD_DIGESTSIZE);
		ripemd_final((void *) thread->state);
		ripemd_digest((void *) thread->state, digest);
		return_val = digest;
		break;
	case MHASH_TIGER:
		digest = hash_malloc(192 >> 3);
		memcpy(digest, (void *) thread->state, 192 >> 3);
		return_val = digest;
		break;
	case MHASH_GOST:
		digest = hash_malloc(32);
		gosthash_final((void *) thread->state, digest);
		return_val = digest;
		break;
	}

	mhash(tmptd, return_val,
	      mhash_get_block_size(thread->algorithm_given));

	if (NULL != return_val) {
		free(return_val);
	}

	free(thread->state);
	free(opad);
	mhash_bzero(thread->hmac_key, thread->hmac_key_size);
	free(thread->hmac_key);
	free(thread);

	return mhash_end(tmptd);
}

WIN32DLL_DEFINE void *mhash_hmac_end(MHASH thread)
{
	return mhash_hmac_end_m(thread, malloc);
}


WIN32DLL_DEFINE
    MHASH mhash_hmac_init(const hashid type, void *key, int keysize,
			  int block)
{
	MHASH ret = MHASH_FAILED;
	MHASH tmptd;
	unsigned char *tmp;
	unsigned char *ipad;
	int i;

	if (block == 0) {
		block = 64;	/* the default for ripemd,md5,sha-1 */
	}

	ret = mhash_init_int(type);

	if (ret != MHASH_FAILED) {
		/* Initial hmac calculations */
		ret->hmac_block = block;

		ipad = malloc(ret->hmac_block);

		if (keysize > ret->hmac_block) {
			tmptd = mhash_init(type);
			mhash(tmptd, key, keysize);
			ret->hmac_key_size = mhash_get_block_size(type);
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
		for (; i < ret->hmac_block; i++) {
			ipad[i] = (0x36);
		}

		mhash(ret, ipad, ret->hmac_block);

		free(ipad);
	}



	return ret;
}

WIN32DLL_DEFINE void mhash_free(void *ptr)
{
	free(ptr);
}
