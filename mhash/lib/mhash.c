/*
 *    Copyright (C) 1998 Nikos Mavroyanopoulos
 *    Copyright (C) 1999,2000 Sascha Schumman, Nikos Mavroyanopoulos
 *    Copyright (C) 2001 Nikos Mavroyanopoulos
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


/* $Id: mhash.c,v 1.28 2002/02/10 10:10:08 nmav Exp $ */

#include <stdlib.h>

#include "libdefs.h"

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#include "mhash_int.h"
#include "mhash_crc32.h"
#include "mhash_haval.h"
#include "mhash_md5.h"
#include "mhash_md4.h"
#include "mhash_sha1.h"
#include "mhash_tiger.h"
#include "mhash_ripemd.h"
#include "mhash_sha256.h"
#include "mhash_adler32.h"
#include "gosthash.h"

/* 19/03/2000 Changes for better thread handling --nikos */

#define MAX_BLOCK_SIZE 64

#define MHASH_ENTRY(name, blksize, hash_pblock) \
	{ #name, name, blksize, hash_pblock }

struct mhash_hash_entry {
	char *name;
	hashid id;
	size_t blocksize;
	size_t hash_pblock;
};

static const mhash_hash_entry algorithms[] = {
	MHASH_ENTRY(MHASH_CRC32, 4, 0),
	MHASH_ENTRY(MHASH_ADLER32, 4, 0),
	MHASH_ENTRY(MHASH_MD5, 16, 64),
	MHASH_ENTRY(MHASH_MD4, 16, 64),
	MHASH_ENTRY(MHASH_SHA1, 20, 64),
	MHASH_ENTRY(MHASH_SHA256, 32, 64),
	MHASH_ENTRY(MHASH_HAVAL256, 32, 128),
	MHASH_ENTRY(MHASH_HAVAL128, 16, 128),
	MHASH_ENTRY(MHASH_HAVAL160, 20, 128),
	MHASH_ENTRY(MHASH_HAVAL192, 24, 128),
	MHASH_ENTRY(MHASH_HAVAL224, 28, 128),
	MHASH_ENTRY(MHASH_RIPEMD160, 20, 64),
	MHASH_ENTRY(MHASH_TIGER, 24, 64),
	MHASH_ENTRY(MHASH_TIGER128, 16, 64),
	MHASH_ENTRY(MHASH_TIGER160, 20, 64),
	MHASH_ENTRY(MHASH_GOST, 32, 0),
	MHASH_ENTRY(MHASH_CRC32B, 4, 0),
	{0}
};

#define MHASH_LOOP(b) \
	const mhash_hash_entry *p; \
	for(p = algorithms; p->name != NULL; p++) { b ; }

#define MHASH_ALG_LOOP(a) \
	MHASH_LOOP( if(p->id == type) { a; break; } )

#ifndef MMAX
# define MMAX(x,y) (x>y?x:y)
#endif

WIN32DLL_DEFINE size_t mhash_count(void)
{
	hashid count = 0;

	MHASH_LOOP( count = MMAX( p->id, count) );

	return count;
}

WIN32DLL_DEFINE size_t mhash_get_block_size(hashid type)
{
	size_t ret = 0;

	MHASH_ALG_LOOP(ret = p->blocksize);
	return ret;
}

/* function created in order for mhash to compile under WIN32 */
char *mystrdup(char *str)
{
	char *ret;
	if (str==NULL) return NULL;
	
	if ( (ret = malloc(strlen(str) + 1)) == NULL) return NULL;
	strcpy(ret, str);

	return ret;

}

WIN32DLL_DEFINE hashid mhash_get_mhash_algo( MHASH tmp) {
	return tmp->algorithm_given;
}

WIN32DLL_DEFINE char *mhash_get_hash_name(hashid type)
{
	char *ret = NULL;

	/* avoid prefix */
	MHASH_ALG_LOOP( ret = p->name);

	if (ret!=NULL) ret += sizeof("MHASH_") - 1;
	
	return mystrdup(ret);
}

WIN32DLL_DEFINE const char *mhash_get_hash_name_static(hashid type)
{
	char *ret = NULL;

	/* avoid prefix */
	MHASH_ALG_LOOP( ret = p->name);
	
	if ( ret !=NULL) ret+= sizeof("MHASH_") - 1;

	return ret;
}

MHASH mhash_cp(MHASH from) {
MHASH ret;

	if ( (ret = malloc(sizeof(MHASH_INSTANCE))) == NULL) return MHASH_FAILED;
	memcpy(ret, from, sizeof(MHASH_INSTANCE));
	
	/* copy the internal state also */
	if ( (ret->state=malloc(ret->state_size)) == NULL) return MHASH_FAILED;
	memcpy( ret->state, from->state, ret->state_size);
	
	/* copy the key in case of hmac*/
	if (ret->hmac_key_size!=0) {
		if ((ret->hmac_key=malloc(ret->hmac_key_size)) == NULL) return MHASH_FAILED;
		memcpy(ret->hmac_key, from->hmac_key, ret->hmac_key_size);
	}
	return ret;

}
MHASH mhash_init_int(const hashid type)
{
	MHASH ret;

	if ( (ret = malloc( sizeof(MHASH_INSTANCE))) == NULL) return MHASH_FAILED;
	ret->algorithm_given = type;
	ret->hmac_key = NULL;
	ret->state = NULL;
	ret->hmac_key_size = 0;
	
	switch (type) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		ret->state_size = sizeof(word32);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		mhash_clear_crc32((void *) ret->state);
		break;
	case MHASH_ADLER32:
		ret->state_size = sizeof(word32);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		mhash_clear_adler32((void *) ret->state);
		break;
	case MHASH_MD5:
		ret->state_size = sizeof(MD5_CTX);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		MD5Init((void *) ret->state);
		break;
	case MHASH_MD4:
		ret->state_size = sizeof(MD4_CTX);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		MD4Init((void *) ret->state);
		break;
	case MHASH_SHA1:
		ret->state_size = sizeof(SHA_CTX);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		sha_init((void *) ret->state);
		break;
	case MHASH_SHA256:
		ret->state_size = sizeof( SHA256_CTX);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		sha256_init((void *) ret->state);
		break;
	case MHASH_HAVAL256:
		ret->state_size = sizeof(havalContext);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		havalInit((void *) ret->state, 3, 256);
		break;
	case MHASH_HAVAL224:
		ret->state_size = sizeof(havalContext);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		havalInit((void *) ret->state, 3, 224);
		break;
	case MHASH_HAVAL192:
		ret->state_size = sizeof(havalContext);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		havalInit((void *) ret->state, 3, 192);
		break;
	case MHASH_HAVAL160:
		ret->state_size = sizeof(havalContext);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		havalInit((void *) ret->state, 3, 160);
		break;
	case MHASH_HAVAL128:
		ret->state_size = sizeof(havalContext);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		havalInit((void *) ret->state, 3, 128);
		break;
	case MHASH_RIPEMD160:
		ret->state_size = sizeof(RIPEMD_CTX);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		ripemd_init((void *) ret->state);
		break;
	case MHASH_TIGER:
	case MHASH_TIGER128:
	case MHASH_TIGER160:
		ret->state_size = sizeof(TIGER_CTX);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		tiger_init((void*) ret->state);
		break;
	case MHASH_GOST:
		ret->state_size = sizeof(GostHashCtx);
		if ( (ret->state = malloc(ret->state_size)) == NULL) {
			free(ret);
			return MHASH_FAILED;
		}
		gosthash_reset((void *) ret->state);
		break;
	default:
		free(ret);
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
		mhash_crc32((void *) thread->state, plaintext, size);
		break;
	case MHASH_ADLER32:
		mhash_adler32((void *) thread->state, plaintext, size);
		break;
	case MHASH_CRC32B:
		crc32b((void *) thread->state, plaintext, size);
		break;
	case MHASH_MD5:
		MD5Update((void *) thread->state, plaintext, size);
		break;
	case MHASH_MD4:
		MD4Update((void *) thread->state, plaintext, size);
		break;
	case MHASH_SHA1:
		sha_update((void *) thread->state, (void *) plaintext,
			   size);
		break;
	case MHASH_SHA256:
		sha256_update((void *) thread->state, (void *) plaintext, size);
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
	case MHASH_TIGER160:
	case MHASH_TIGER128:
		tiger_update((void*)thread->state, (void*)plaintext, size);
		break;
	case MHASH_GOST:
		gosthash_update((void *) thread->state, plaintext, size);
		break;
	}

	return 0;
}


WIN32DLL_DEFINE
    void mhash_deinit(MHASH thread, void *result)
{

	if (result!=NULL)
	switch (thread->algorithm_given) {
	case MHASH_CRC32:
	case MHASH_CRC32B:
		mhash_get_crc32(result, (void *) thread->state);
		break;
	case MHASH_ADLER32:
		mhash_get_adler32(result, (void *) thread->state);
		break;
	case MHASH_MD5:
		MD5Final( result, (void *) thread->state);
		break;
	case MHASH_MD4:
		MD4Final( result, (void *) thread->state);
		break;
	case MHASH_SHA1:
		sha_final((void *) thread->state);
		sha_digest((void *) thread->state, result);
		break;
	case MHASH_SHA256:
		sha256_final((void *) thread->state);
		sha256_digest((void *) thread->state, result);
		break;
	case MHASH_HAVAL256:
	case MHASH_HAVAL224:
	case MHASH_HAVAL192:
	case MHASH_HAVAL160:
	case MHASH_HAVAL128:
		havalFinal((void *) thread->state, result);
		break;
	case MHASH_RIPEMD160:
		ripemd_final((void *) thread->state);
		ripemd_digest((void *) thread->state, result);
		break;
	case MHASH_TIGER:
		tiger_final((void*) thread->state);
		tiger_digest((void *) thread->state, result);
		break;
	case MHASH_TIGER128:
		tiger_final((void*) thread->state);
		tiger128_digest((void *) thread->state, result);
		break;
	case MHASH_TIGER160:
		tiger_final((void*) thread->state);
		tiger160_digest((void *) thread->state, result);
		break;
	case MHASH_GOST:
		gosthash_final((void *) thread->state, result);
		break;
	}

	if (NULL != thread->state) {
		free(thread->state);
	}
	free(thread);

	return;
}

WIN32DLL_DEFINE
    void *mhash_end_m(MHASH thread, void *(*hash_malloc) (size_t))
{
	void *digest;
	int size;

	size = mhash_get_block_size( thread->algorithm_given);
	
	digest = hash_malloc( size);
	if (digest==NULL) return NULL;
	
	mhash_deinit( thread, digest);
	
	return digest;
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
    int mhash_hmac_deinit(MHASH thread, void *result)
{
	unsigned char *opad;
	unsigned char _opad[MAX_BLOCK_SIZE];
	MHASH tmptd;
	int i, opad_alloc = 0;

	if (thread->hmac_block > MAX_BLOCK_SIZE) {
		opad = malloc(thread->hmac_block);
		if (opad == NULL) return -1;
		opad_alloc = 1;
	} else {
		opad = _opad;
	}


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
		mhash_get_crc32( result, (void *) thread->state);
		break;
	case MHASH_ADLER32:
		mhash_get_adler32( result, (void *) thread->state);
		break;
	case MHASH_MD5:
		MD5Final( result, (void *) thread->state);
		break;
	case MHASH_MD4:
		MD4Final( result, (void *) thread->state);
		break;
	case MHASH_SHA1:
		sha_final((void *) thread->state);
		sha_digest((void *) thread->state, result);
		break;
	case MHASH_SHA256:
		sha256_final((void *) thread->state);
		sha256_digest((void *) thread->state, result);
		break;
	case MHASH_HAVAL256:
	case MHASH_HAVAL224:
	case MHASH_HAVAL192:
	case MHASH_HAVAL160:
	case MHASH_HAVAL128:
		havalFinal((void *) thread->state, result);
		break;
	case MHASH_RIPEMD160:
		ripemd_final((void *) thread->state);
		ripemd_digest((void *) thread->state, result);
		break;
	case MHASH_TIGER:
		tiger_final((void *) thread->state);
		tiger_digest((void *) thread->state, result);
		break;
	case MHASH_TIGER128:
		tiger_final((void *) thread->state);
		tiger128_digest((void *) thread->state, result);
		break;
	case MHASH_TIGER160:
		tiger_final((void *) thread->state);
		tiger160_digest((void *) thread->state, result);
		break;
	case MHASH_GOST:
		gosthash_final((void *) thread->state, result);
		break;
	}

	if (result!=NULL)
		mhash(tmptd, result,
		      mhash_get_block_size(thread->algorithm_given));

	free(thread->state);

	if (opad_alloc!=0) free(opad);
	
	mhash_bzero(thread->hmac_key, thread->hmac_key_size);
	free(thread->hmac_key);
	free(thread);

	mhash_deinit(tmptd, result);

	return 0;
}


WIN32DLL_DEFINE
    void *mhash_hmac_end_m(MHASH thread, void *(*hash_malloc) (size_t))
{
	void *digest;

	digest =
	    hash_malloc(mhash_get_block_size
			(thread->algorithm_given));
	if (digest == NULL) return NULL;

	mhash_hmac_deinit( thread, digest);
	
	return digest;
	
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
	unsigned char *ipad;
	unsigned char _ipad[MAX_BLOCK_SIZE];
	int i, ipad_alloc=0;

	if (block == 0) {
		block = 64;	/* the default for ripemd,md5,sha-1 */
	}

	ret = mhash_init_int(type);

	if (ret != MHASH_FAILED) {
		/* Initial hmac calculations */
		ret->hmac_block = block;

		if ( ret->hmac_block > MAX_BLOCK_SIZE) {
			ipad = malloc(ret->hmac_block);
			if (ipad == NULL) return MHASH_FAILED;
			ipad_alloc = 1;
		} else {
			ipad = _ipad;
		}
		
		if (keysize > ret->hmac_block) {
			tmptd = mhash_init(type);
			mhash(tmptd, key, keysize);
			ret->hmac_key_size = mhash_get_block_size(type);
			ret->hmac_key = mhash_end(tmptd);
		} else {
			ret->hmac_key = calloc(1, ret->hmac_block);
			memcpy(ret->hmac_key, key, keysize);
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

		if (ipad_alloc!=0) free(ipad);
	}


	return ret;
}

WIN32DLL_DEFINE void mhash_free(void *ptr)
{
	free(ptr);
}

/*
  Saves the state of a hashing algorithm such that it can be
  restored at some later point in time using
  mhash_restore_state().
  
  mem_size should contain the size of the given _mem pointer.
  Otherwise the required size will be copied there.

  Original version and idea by Blake Stephen <Stephen.Blake@veritect.com>
*/
WIN32DLL_DEFINE int mhash_save_state_mem(MHASH thread, void *_mem, int* mem_size )
{
	int tot_size, pos;
	unsigned char* mem = _mem;
	
	tot_size = sizeof(thread->algorithm_given) + sizeof(thread->hmac_key_size)
		+ sizeof(thread->hmac_block) + thread->hmac_key_size +
		+ sizeof(thread->state_size) + thread->state_size;
	
	if ( *mem_size < tot_size) {
		*mem_size = tot_size;
		return -1;
	}
	
	if ( mem != NULL) {
		pos = 0;
		memcpy( mem, &thread->algorithm_given, sizeof(thread->algorithm_given));
		pos = sizeof( thread->algorithm_given);
		
		memcpy( &mem[pos], &thread->hmac_key_size, sizeof(thread->hmac_key_size));
		pos += sizeof(thread->hmac_key_size);

		memcpy( &mem[pos], &thread->hmac_block, sizeof(thread->hmac_block));
		pos += sizeof(thread->hmac_block);

		memcpy( &mem[pos], thread->hmac_key, thread->hmac_key_size);
		pos += thread->hmac_key_size;

		memcpy( &mem[pos], &thread->state_size, sizeof(thread->state_size));
		pos += sizeof(thread->state_size);

		memcpy( &mem[pos], thread->state, thread->state_size);
		pos += thread->state_size;

	}
	return 0;
}


/*
  Restores the state of a hashing algorithm that was saved
  using mhash_save_state(). Use like mhash_init.
*/
WIN32DLL_DEFINE MHASH mhash_restore_state_mem(void* _mem)
{
	unsigned char* mem = _mem;
	hashid algorithm_given;
	MHASH ret = MHASH_FAILED;
	int pos;

	if (mem==NULL)
		return ret;

	memcpy( &algorithm_given, mem, sizeof(algorithm_given));
	
	if ((ret = mhash_init(algorithm_given)) == MHASH_FAILED) {
		return ret;
	}

	ret->algorithm_given = algorithm_given;
	
	pos = sizeof(algorithm_given);

 	memcpy( &ret->hmac_key_size, &mem[pos], sizeof(ret->hmac_key_size));
	pos += sizeof( ret->hmac_key_size);
		
	memcpy( &ret->hmac_block, &mem[pos], sizeof(ret->hmac_block));
	pos += sizeof(ret->hmac_block);

	if (ret->hmac_key_size != 0) {
		ret->hmac_key = malloc( ret->hmac_key_size);
		if (ret->hmac_key==NULL) goto freeall;
	
		memcpy( ret->hmac_key, &mem[pos], ret->hmac_key_size);
		pos += sizeof(ret->hmac_key_size);
	}

	memcpy( &ret->state_size, &mem[pos], sizeof(ret->state_size));
	pos += sizeof( ret->state_size);

	ret->state = malloc( ret->state_size);
	if (ret->state==NULL) goto freeall;

	memcpy( ret->state, &mem[pos], ret->state_size);
	pos += ret->state_size;

	return ret;

	freeall:
		/* This uses too much internals
		 */
		free( ret->state);
		free( ret->hmac_key);
		free( ret);
		return MHASH_FAILED;
}

