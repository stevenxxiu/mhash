/*
 *    Copyright (C) 1998 Nikos Mavroyanopoulos
 *    Copyright (C) 1999,2000 Sascha Schumman, Nikos Mavroyanopoulos
 *    Copyright (C) 2001 Nikos Mavroyanopoulos
 *    Copyright (C) 2006 Jonathan Day
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


/* $Id: mhash.c,v 1.42 2006/01/10 04:40:48 imipak Exp $ */

#include <libdefs.h>
#include <mhash_int.h>

WIN32DLL_DEFINE
    mutils_error mhash_hmac_deinit(MHASH td, void *result)
{
	mutils_word8 *opad;
	mutils_word8 _opad[MAX_BLOCK_SIZE];
	MHASH tmptd;
	mutils_word32 i;
	mutils_word32 opad_alloc = 0;

	if (td->hmac_block > MAX_BLOCK_SIZE)
	{
		opad = mutils_malloc(td->hmac_block);
		if (opad == NULL)
		{
			return(-MUTILS_SYSTEM_RESOURCE_ERROR);
		}
		opad_alloc = 1;
	}
	else
	{
		opad = _opad;
	}


	for (i = 0; i < td->hmac_key_size; i++)
	{
		opad[i] = (0x5C) ^ td->hmac_key[i];
	}

	for (; i < td->hmac_block; i++)
	{
		opad[i] = (0x5C);
	}

	tmptd = mhash_init(td->algorithm_given);

	mhash(tmptd, opad, td->hmac_block);

	if (td->final_func != NULL)
	{
		td->final_func(td->state);
	}

	if (td->deinit_func != NULL)
	{
		td->deinit_func(td->state, result);
	}

	if (result != NULL)
	{
		mhash(tmptd, result,
		      mhash_get_block_size(td->algorithm_given));
	}

	mutils_free(td->state);

	if (opad_alloc!=0)
	{
		mutils_free(opad);
	}

	mutils_bzero(td->hmac_key, td->hmac_key_size);
	mutils_free(td->hmac_key);
	mutils_free(td);

	mhash_deinit(tmptd, result);

	return(MUTILS_OK);
}


WIN32DLL_DEFINE
    void *mhash_hmac_end_m(MHASH td, void *(*hash_malloc) (mutils_word32))
{
	void *digest;

	digest =
	    hash_malloc(mhash_get_block_size
			(td->algorithm_given));

	if (digest == NULL)
	{
		return(NULL);
	}

	mhash_hmac_deinit(td, digest);
	
	return(digest);
}

WIN32DLL_DEFINE void *mhash_hmac_end(MHASH td)
{
	return mhash_hmac_end_m(td, mutils_malloc);
}

WIN32DLL_DEFINE
    MHASH mhash_hmac_init(__const hashid type, void *key, mutils_word32 keysize,
			  mutils_word32 block)
{
	MHASH ret = MHASH_FAILED;
	MHASH tmptd;
	mutils_word8 *ipad;
	mutils_word8 _ipad[MAX_BLOCK_SIZE];
	mutils_word32 i;
	mutils_boolean ipad_alloc = MUTILS_FALSE;

	if (block == 0)
	{
		block = 64;	/* the default for ripemd,md5,sha-1 */
	}

	ret = mhash_init_int(type);

	if (ret != MHASH_FAILED) {
		/* Initial hmac calculations */
		ret->hmac_block = block;

		if ( ret->hmac_block > MAX_BLOCK_SIZE)
		{
			ipad = mutils_malloc(ret->hmac_block);
			if (ipad == NULL)
			{
				return MHASH_FAILED;
			}
			ipad_alloc = MUTILS_TRUE;
		}
		else
		{
			ipad = _ipad;
		}
		
		if (keysize > ret->hmac_block)
		{
			tmptd = mhash_init(type);
			mhash(tmptd, key, keysize);
			ret->hmac_key_size = mhash_get_block_size(type);
			ret->hmac_key = mhash_end(tmptd);
		}
		else
		{
			ret->hmac_key = mutils_malloc(ret->hmac_block);
			mutils_bzero(ret->hmac_key, ret->hmac_block);
			mutils_memcpy(ret->hmac_key, key, keysize);
			ret->hmac_key_size = ret->hmac_block;
		}

		/* IPAD */

		for (i = 0; i < ret->hmac_key_size; i++)
		{
			ipad[i] = (0x36) ^ ret->hmac_key[i];
		}
		for (; i < ret->hmac_block; i++)
		{
			ipad[i] = (0x36);
		}

		mhash(ret, ipad, ret->hmac_block);

		if (ipad_alloc == MUTILS_TRUE)
		{
			mutils_free(ipad);
		}
	}

	return(ret);
}
