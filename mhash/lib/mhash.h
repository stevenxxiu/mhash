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


#ifndef MHASH_H
#define MHASH_H

/* $Id: mhash.h,v 1.24 2005/01/12 17:37:04 imipak Exp $ */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <mhash_config.h>

#define MHASH_API_NONE		0
#define MHASH_API_CLASSIC	1
#define MHASH_API_FAMILY	2

#define MHASH_API_VERSION 20040112
#define MHASH_API_TYPE MHASH_API_CLASSIC
/* #define MHASH_API_TYPE MHASH_API_FAMILY */
#define MHASH_API_FULL

/* These aliases are actually quite useful and so will be kept */

#define MHASH_HAVAL MHASH_HAVAL256
#define MHASH_TIGER MHASH_TIGER192

/* these are for backwards compatibility and will 
   be removed at some time */

#ifdef MHASH_BACKWARDS_COMPATIBLE
# define hmac_mhash_init mhash_hmac_init
# define hmac_mhash_end mhash_hmac_end
#endif

/* typedefs */ struct MHASH_INSTANCE;
	typedef struct MHASH_INSTANCE *MHASH;

#if MHASH_API_TYPE == MHASH_API_CLASSIC
	enum hashid {
#if defined(ENABLE_CRC32) || defined(MHASH_API_FULL)
		MHASH_CRC32	= 0,
		MHASH_CRC32B	= 9,
#endif
#if defined(ENABLE_ADLER32) || defined(MHASH_API_FULL)
		MHASH_ADLER32	= 18,
#endif
#if defined(ENABLE_MD2) || defined(MHASH_API_FULL)
		MHASH_MD2	= 27,
#endif
#if defined(ENABLE_MD4) || defined(MHASH_API_FULL)
		MHASH_MD4	= 16,
#endif
#if defined(ENABLE_MD5) || defined(MHASH_API_FULL)
		MHASH_MD5	= 1,
#endif
#if defined(ENABLE_RIPEMD) || defined(MHASH_API_FULL)
		MHASH_RIPEMD160 = 5,
		MHASH_RIPEMD128 = 22,
		MHASH_RIPEMD256 = 23,
		MHASH_RIPEMD320 = 24,
#endif
#if defined(ENABLE_SHA1) || defined(MHASH_API_FULL)
		MHASH_SHA1	= 2,
#endif
#if defined(ENABLE_SHA256_SHA224) || defined(MHASH_API_FULL)
		MHASH_SHA224	= 19,
		MHASH_SHA256	= 17,
#endif
#if defined(ENABLE_SHA512_SHA384) || defined(MHASH_API_FULL)
		MHASH_SHA384	= 21,
		MHASH_SHA512	= 20,
#endif
#if defined(ENABLE_HAVAL) || defined(MHASH_API_FULL)
		MHASH_HAVAL128	= 13,
		MHASH_HAVAL160	= 12,
		MHASH_HAVAL192	= 11,
		MHASH_HAVAL224	= 10,
		MHASH_HAVAL256	= 3,	/* 3 passes */
#endif
#if defined(ENABLE_HAVAL) || defined(MHASH_API_FULL)
		MHASH_TIGER128	= 14,
		MHASH_TIGER160	= 15,
		MHASH_TIGER192	= 7,
#endif
#if defined(ENABLE_GOST) || defined(MHASH_API_FULL)
		MHASH_GOST	= 8,
#endif
#if defined(ENABLE_WHIRLPOOL) || defined(MHASH_API_FULL)
		MHASH_WHIRLPOOL = 21,
#endif
#if defined(ENABLE_SNEFRU) || defined(MHASH_API_FULL)
		MHASH_SNEFRU128 = 25,  /* 8 passes */
		MHASH_SNEFRU256 = 26,  /* 8 passes */
#endif
	};
#endif

/* No idea if this will prove of any value. The idea here is to map the
 * hash function according to the general family to which it belongs.
 *
 * The units column denotes which hash within a given group it is.
 * The tens column denotes which group within a given family it is.
 * The remaining columns denote the family.
 */

#if MHASH_API_TYPE == MHASH_API_FAMILY
	enum hashid {
#if defined(ENABLE_CRC32) || defined(MHASH_API_FULL)
		MHASH_CRC32	= 0001,
		MHASH_CRC32B	= 0002,
#endif
#if defined(ENABLE_ADLER32) || defined(MHASH_API_FULL)
		MHASH_ADLER32	= 0011,
#endif
#if defined(ENABLE_MD2) || defined(MHASH_API_FULL)
		MHASH_MD2	= 0101,
#endif
#if defined(ENABLE_MD4) || defined(MHASH_API_FULL)
		MHASH_MD4	= 0111,
#endif
#if defined(ENABLE_RIPEMD) || defined(MHASH_API_FULL)
		MHASH_RIPEMD128 = 0112,
		MHASH_RIPEMD160 = 0113,
		MHASH_RIPEMD256 = 0114,
		MHASH_RIPEMD320 = 0115,
#endif
#if defined(ENABLE_MD5) || defined(MHASH_API_FULL)
		MHASH_MD5	= 0121,
#endif
#if defined(ENABLE_SHA1) || defined(MHASH_API_FULL)
		MHASH_SHA1	= 0201,
#endif
#if defined(ENABLE_SHA256_SHA224) || defined(MHASH_API_FULL)
		MHASH_SHA224	= 0201,
		MHASH_SHA256	= 0202,
#endif
#if defined(ENABLE_SHA512_SHA384) || defined(MHASH_API_FULL)
		MHASH_SHA384	= 0203,
		MHASH_SHA512	= 0204,
#endif
#if defined(ENABLE_HAVAL) || defined(MHASH_API_FULL)
		MHASH_HAVAL128	= 0301,
		MHASH_HAVAL160	= 0302,
		MHASH_HAVAL192	= 0303,
		MHASH_HAVAL224	= 0304,
		MHASH_HAVAL256	= 0305,	/* 3 passes */
#endif
#if defined(ENABLE_TIGER) || defined(MHASH_API_FULL)
		MHASH_TIGER128	= 0401,
		MHASH_TIGER160	= 0402,
		MHASH_TIGER192	= 0403,
#endif
#if defined(ENABLE_GOST) || defined(MHASH_API_FULL)
		MHASH_GOST	= 0501,
#endif
#if defined(ENABLE_WHIRLPOOL) || defined(MHASH_API_FULL)
		MHASH_WHIRLPOOL = 0601,
#endif
#if defined(ENABLE_SNEFRU) || defined(MHASH_API_FULL)
		MHASH_SNEFRU128 = 0701,  /* 8 passes */
		MHASH_SNEFRU256 = 0702,  /* 8 passes */
#endif
	};
#endif

	enum keygenid {
		KEYGEN_MCRYPT,	/* The key generator used in mcrypt */
		KEYGEN_ASIS,	/* Just returns the password as binary key */
		KEYGEN_HEX,	/* Just converts a hex key into a binary one */
		KEYGEN_PKDES,	/* The transformation used in Phil Karn's DES
				 * encryption program */
		KEYGEN_S2K_SIMPLE,	/* The OpenPGP (rfc2440) Simple S2K */
		KEYGEN_S2K_SALTED,	/* The OpenPGP Salted S2K */
		KEYGEN_S2K_ISALTED	/* The OpenPGP Iterated Salted S2K */
	};

	typedef enum hashid hashid;
	typedef enum keygenid keygenid;

	typedef struct mhash_hash_entry mhash_hash_entry;

	typedef struct keygen {
		hashid 		hash_algorithm[2];
		unsigned int	count;
		void*		salt;
		int		salt_size;
	} KEYGEN;


#define MHASH_FAILED ((MHASH) 0x0)

/* information prototypes */

	size_t mhash_count(void);
	size_t mhash_get_block_size(hashid type);
	char *mhash_get_hash_name(hashid type);
	const char *mhash_get_hash_name_static(hashid type);
	void mhash_free(void *ptr);

/* initializing prototypes */

	MHASH mhash_init(hashid type);

/* copy prototypes */

	MHASH mhash_cp(MHASH);

/* update prototype */

	int mhash(MHASH thread, const void *plaintext, size_t size);

/* finalizing prototype */

	void *mhash_end(MHASH thread);
	void *mhash_end_m(MHASH thread, void *(*hash_malloc) (size_t));
	void mhash_deinit(MHASH thread, void *result);

/* informational */
	size_t mhash_get_hash_pblock(hashid type);

	hashid mhash_get_mhash_algo(MHASH);

/* HMAC */
	MHASH mhash_hmac_init(const hashid type, void *key, int keysize,
			      int block);
	void *mhash_hmac_end_m(MHASH thread, void *(*hash_malloc) (size_t));
	void *mhash_hmac_end(MHASH thread);
	int mhash_hmac_deinit(MHASH thread, void *result);

/* Save state functions */
	int mhash_save_state_mem(MHASH thread, void *mem, int* mem_size );
	MHASH mhash_restore_state_mem(void* mem);

/* Key generation functions */
	int mhash_keygen(keygenid algorithm, hashid opt_algorithm,
			 unsigned long count, void *keyword, int keysize,
			 void *salt, int saltsize, unsigned char *password,
			 int passwordlen);
	int mhash_keygen_ext(keygenid algorithm, KEYGEN data,
		 void *keyword, int keysize,
		 unsigned char *password, int passwordlen);

	char *mhash_get_keygen_name(keygenid type);
	const char *mhash_get_keygen_name_static(hashid type);

	size_t mhash_get_keygen_salt_size(keygenid type);
	size_t mhash_get_keygen_max_key_size(keygenid type);
	size_t mhash_keygen_count(void);
	int mhash_keygen_uses_salt(keygenid type);
	int mhash_keygen_uses_count(keygenid type);
	int mhash_keygen_uses_hash_algorithm(keygenid type);


#ifdef __cplusplus
}
#endif
#endif				/* !MHASH_H */
