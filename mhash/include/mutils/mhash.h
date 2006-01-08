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


#if !defined(__MHASH_H)
#define __MHASH_H

/* $Id: mhash.h,v 1.24 2005/01/12 17:37:04 imipak Exp $ */

#ifdef __cplusplus
extern "C" {
#endif

#include <mutils/mincludes.h>
#include <mutils/mglobal.h>
#include <mutils/mutils.h>
#include <mutils/mtypes.h>

#define MHASH_API_VERSION 20020524

/* these are for backwards compatibility and will 
   be removed at some time */
#ifdef MHASH_BACKWARDS_COMPATIBLE
# define MHASH_HAVAL MHASH_HAVAL256
# define MHASH_TIGER192 MHASH_TIGER
# define hmac_mhash_init mhash_hmac_init
# define hmac_mhash_end mhash_hmac_end
#endif

/* typedefs */

typedef struct mhash_hash_entry mhash_hash_entry;

/* information prototypes */

size_t mhash_count(void);
size_t mhash_get_block_size(hashid type);
mutils_word8 *mhash_get_hash_name(hashid type);
const mutils_word8 *mhash_get_hash_name_static(hashid type);
void mhash_free(void *ptr);

/* initializing prototypes */

MHASH mhash_init(hashid type);

/* copy prototypes */

MHASH mhash_cp(MHASH);

/* update prototype */

mutils_boolean mhash(MHASH thread, const void *plaintext, size_t size);

/* finalizing prototype */

void *mhash_end(MHASH thread);
void *mhash_end_m(MHASH thread, void *(*hash_malloc) (size_t));
void mhash_deinit(MHASH thread, void *result);

/* informational */

size_t mhash_get_hash_pblock(hashid type);
hashid mhash_get_mhash_algo(MHASH);

/* HMAC */

MHASH mhash_hmac_init(const hashid type, void *key, mutils_word32 keysize, mutils_word32 block);
void *mhash_hmac_end_m(MHASH thread, void *(*hash_malloc) (size_t));
void *mhash_hmac_end(MHASH thread);
mutils_boolean mhash_hmac_deinit(MHASH thread, void *result);

/* Save state functions */

mutils_boolean mhash_save_state_mem(MHASH thread, void *mem, mutils_word32 *mem_size );
MHASH mhash_restore_state_mem(void *mem);

/* Key generation functions */

mutils_error mhash_keygen(keygenid algorithm, hashid opt_algorithm,
			  mutils_word64 count,
			  void *keyword, mutils_word32 keysize,
			  void *salt, mutils_word32 saltsize,
			  mutils_word8 *password, mutils_word32 passwordlen);
mutils_error mhash_keygen_ext(keygenid algorithm, KEYGEN data,
			      void *keyword, mutils_word32 keysize,
			      mutils_word8 *password, mutils_word32 passwordlen);

mutils_word8 *mhash_get_keygen_name(keygenid type);
const mutils_word8 *mhash_get_keygen_name_static(hashid type);

size_t mhash_get_keygen_salt_size(keygenid type);
size_t mhash_get_keygen_max_key_size(keygenid type);
size_t mhash_keygen_count(void);

mutils_boolean mhash_keygen_uses_salt(keygenid type);
mutils_boolean mhash_keygen_uses_count(keygenid type);
mutils_boolean mhash_keygen_uses_hash_algorithm(keygenid type);

#ifdef __cplusplus
}
#endif
#endif				/* !MHASH_H */
