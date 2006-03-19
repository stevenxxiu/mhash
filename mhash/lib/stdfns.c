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


/*
   $Id: stdfns.c,v 1.2 2006/01/10 03:47:18 imipak Exp $ 
 */

#include "libdefs.h"

/**
 * Some of these are wrappers. The idea is to eventually produce an extremely
 * lightweight set of robust, portable functions that are guaranteed to produce
 * a "safe" result, even with bogus inputs. We can't trust native C libraries
 * to validate inputs.
 */

/*
 * FIXME: This only works if we validate inputs ourselves. At present, we don't
 * check for overflowing buffers. We also assume ranges are 32-bit, but that may
 * not be the case for 64-bit files even on 32-bit OS'. Once we have malloc
 * internals in here, we should switch to pure 64-bit code.
 */

WIN32DLL_DEFINE
void *
mutils_malloc(__const mutils_word32 n)
{
	void *ptr;

	if (n == 0)
	{
		errno = EINVAL;
		return(NULL);		
	}

	ptr = malloc(n);

	if (ptr != NULL)
	{
		mutils_bzero(ptr, n);
	}
	else
	{
		errno = ENOMEM;
	}

	return(ptr);
}

WIN32DLL_DEFINE
void
mutils_free(__const void *ptr)
{
	if (ptr == NULL)
	{
		errno = EINVAL;  
		return;
	}
	free((void *) ptr);
	return;
}

WIN32DLL_DEFINE
void *
mutils_calloc(__const mutils_word32 count, __const mutils_word32 n)
{
	mutils_word32 total;
	void *ptr;

	if ((count == 0) || (n == 0))
	{
		errno = EINVAL;
		return(NULL);
	}

	total = count * n;

	ptr = mutils_malloc(total);

	return(ptr);
}

WIN32DLL_DEFINE
void *
mutils_realloc(__const void *ptr, __const mutils_word32 n)
{
	void *result = NULL;

	if (ptr == NULL)
	{
		result = mutils_malloc(n);
	}
	else
	{
		if (n == 0)
		{
			mutils_free(ptr);
		}
		else
		{
			result = realloc((void *) ptr, n);
		}
	}

	return(result);
}

WIN32DLL_DEFINE
void
mutils_bzero(__const void *s, __const mutils_word32 n)
{
	mutils_word8  *stmp;
	mutils_word32 *ltmp = (mutils_word32 *) s;
	mutils_word32 i;
	mutils_word32 words;
	mutils_word32 remainder;

	if ((s == NULL) || (n == 0))
	{
		return;
	}

	words = n >> 2;
	remainder = n - (words << 2);

	for (i = 0; i < words; i++, ltmp++)
	{
		*ltmp = 0;
	}

	stmp = (mutils_word8 *) ltmp;

	for (i = 0; i < remainder; i++, stmp++)
	{
		*stmp = 0;
	}

	return;
}

WIN32DLL_DEFINE
void *
mutils_memset(__const void *s, __const mutils_word8 c, __const mutils_word32 n)
{
	mutils_word8 *stmp;
	mutils_word32 *ltmp = (mutils_word32 *) s;
	mutils_word32 lump;
	mutils_word32 i;
	mutils_word32 words;
	mutils_word32 remainder;

	if ((s == NULL) || (n == 0))
	{
		return;
	}

	lump = (c << 24) + (c << 16) + (c << 8) + c;

	words = n >> 2;
	remainder = n - (words << 2);

	for (i = 0; i < words; i++, ltmp++)
	{
		*ltmp = lump;
	}

	stmp = (mutils_word8 *) ltmp;

	for (i = 0; i < remainder; i++, stmp++)
	{
		*stmp = c;
	}

	return((void *) s);
}

WIN32DLL_DEFINE
void *
mutils_memcpy(__const void *dest, __const void *src, __const mutils_word32 n)
{
	mutils_word8 *ptr1;
	mutils_word8 *ptr2;
	mutils_word32 *bigptr1;
	mutils_word32 *bigptr2;
	mutils_word32 i;
	mutils_word32 words;
	mutils_word32 remainder;

	if ((dest == NULL) || (src == NULL) || (n == 0))
	{
		return;
	}

	words = n >> 2;
	remainder = n - (words << 2);

	bigptr1 = (mutils_word32 *) dest;
	bigptr2 = (mutils_word32 *) src;

	for (i = 0; i < words; i ++, bigptr1++, bigptr2++)
	{
		*bigptr1 = *bigptr2;
	}

	ptr1 = (mutils_word8 *) bigptr1;
	ptr2 = (mutils_word8 *) bigptr2;

	for (i = 0; i < remainder; i++, ptr1++, ptr2++)
	{
		*ptr1 = *ptr2;
	}

	return((void *) dest);
}

#define MIX32(a) \
	((mutils_word32) \
		(((a & (mutils_word32) 0x000000ffU) << 24) | \
		 ((a & (mutils_word32) 0x0000ff00U) << 8) | \
		 ((a & (mutils_word32) 0x00ff0000U) >> 8) | \
		 ((a & (mutils_word32) 0xff000000U) >> 24)) \
	)

/*
   Byte swap a 32bit integer 
 */
WIN32DLL_DEFINE
mutils_word32
mutils_word32swap(mutils_word32 x)
{
#if defined(WORDS_BIGENDIAN)
	mutils_word32 out = MIX32(x);

	return(out);
#else
	return(x);
#endif
}

/*
   Byte swap a series of 32-bit integers
 */
WIN32DLL_DEFINE
mutils_word32 *
mutils_word32nswap(__const mutils_word32 *x, __const mutils_word32 n, __const mutils_boolean destructive)
{
	mutils_word32 loop;
	mutils_word32 *buffer;
	mutils_word32 *ptr;
	mutils_word32 total;

	if (destructive == MUTILS_FALSE)
	{
		total = n << 2;
		buffer = mutils_malloc(total);
		if (buffer == NULL)
		{
			return(NULL);
		}
		mutils_memcpy(buffer, x, total);
	}
	else
	{
		buffer = (mutils_word32 *) x;
	}

/*
 * Even though this doesn't do anything for little-endian machines, the non-destructive
 * version is intended to always return a fresh buffer, NOT the original buffer.
 */

#if defined(WORDS_BIGENDIAN)
	for (loop = 0, ptr = buffer; loop < n; loop++, ptr++)
	{
		*ptr = MIX32(*ptr);
	}
#endif

	return(buffer);
}

WIN32DLL_DEFINE
void *
mutils_memmove(__const void *dest, __const void *src, __const mutils_word32 n)
{
	mutils_word8 *ptr1;
	mutils_word8 *ptr2;
	mutils_word32 i;
	mutils_word32 *bigptr1;
	mutils_word32 *bigptr2;
	mutils_word32 words;
	mutils_word32 remainder;

	if ((dest == NULL) || (src == NULL) || (n == 0))
	{
		return;
	}

	bigptr1 = (mutils_word32 *) dest;
	bigptr2 = (mutils_word32 *) src;

	words = n >> 2;
	remainder = n - (words << 2);

	for (i = 0; i < words; i++, bigptr1++, bigptr2++)
	{
		*bigptr1 = *bigptr2;
	}

	ptr1 = (mutils_word8 *) bigptr1;
	ptr2 = (mutils_word8 *) bigptr2;

	for (i = 0; i < remainder; i++, ptr1++, ptr2++)
	{
		*ptr1 = *ptr2;
	}

	return((void *) dest);
}

WIN32DLL_DEFINE
int
mutils_memcmp(__const void *s1, __const void *s2, __const mutils_word32 n)
{
	if (n == 0)
	{
		return(0);
	}
	if (s1 == NULL)
	{
		if (s2 == NULL)
		{
			return(0);
		}
		return(-MAXINT);
	}
	if (s2 == NULL)
	{
		return(MAXINT);
	}

	return(memcmp(s1, s2, n));
}

/* Ugh. This could do nasty things, if a string isn't correctly terminated,
 * particularly as memory can be larger than can be stored in a 32-bit word.
 * If it is possible to produce an incorrect result, or segfault, then it
 * is not a robust solution.
 */

WIN32DLL_DEFINE
mutils_word32
mutils_strlen(__const mutils_word8 *str)
{
	mutils_word32 ret;
	mutils_word8 *endStr = (mutils_word8 *) str;

	if (str == NULL)
	{
		return(0);
	}

	while (*endStr != 0)
	{
		endStr++;
	}

	ret = endStr - str;

	return(ret);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strdup(__const mutils_word8 *str)
{
	mutils_word8 *ret = NULL;
	mutils_word8 *ptr1;
	mutils_word8 *ptr2;
	mutils_word32 len;

	if (str == NULL)
	{
		return(NULL);
	}

	len = mutils_strlen(str) + 1;

	ret = (mutils_word8 *) mutils_malloc(len);

	if (ret != NULL)
	{
		mutils_memcpy(ret, str, len);
	}

	return(ret);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strcat(__const mutils_word8 *dest, __const mutils_word8 *src)
{
	mutils_word8 *appendAt;
	mutils_word32 len;

	if (dest == NULL)
	{
		return(NULL);
	}
	else
	{
		appendAt = (mutils_word8 *) dest + mutils_strlen(dest);
	}
	if (src != NULL)
	{
		len = mutils_strlen(src) + 1;
		mutils_memcpy(appendAt, src, len);
	}
	return((mutils_word8 *) dest);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strcpy(__const mutils_word8 *dest, __const mutils_word8 *src)
{
	mutils_word32 len;

	if (dest == NULL)
	{
		return(NULL);
	}

	len = mutils_strlen(src) + 1;

	/*
	 * FIXME: Non-overwritten data in dest MUST be zeroed out.
	 * We can't just do a strlen, though, as we can't assume
	 * dest holds a string.
	 */
	
	mutils_memcpy(dest, src, len);
	
	return((mutils_word8 *) dest);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strncpy(__const mutils_word8 *dest, __const mutils_word8 *src, __const mutils_word32 n)
{
	mutils_word32 len;
	mutils_word8 *ptr;

	if (dest == NULL)
	{
		return(NULL);
	}

	if (n == 0)
	{
		return(NULL);
	}

	len = strlen(src) + 1;

	mutils_memcpy(dest, src, len);

	ptr = (mutils_word8 *) dest + len;

	len = n - len;

	if (len > 0)
	{
		mutils_bzero(ptr, len);
	}

	return((mutils_word8 *) dest);
}

WIN32DLL_DEFINE
int
mutils_strcmp(__const mutils_word8 *src1, __const mutils_word8 *src2)
{
	if (src1 == NULL)
	{
		if (src2 == NULL)
		{
			return(0);
		}
		return(-MAXINT);
	}
	if (src2 == NULL)
	{
		return(MAXINT);
	}
	return(strcmp((char *) src1, (char *) src2));
}

WIN32DLL_DEFINE
int
mutils_strncmp(__const mutils_word8 *src1, __const mutils_word8 *src2, __const mutils_word32 n)
{
	if (n == 0)
	{
		return(0);
	}
	if (src1 == NULL)
	{
		if (src2 == NULL)
		{
			return(0);
		}
		return(-MAXINT);
	}
	if (src2 == NULL)
	{
		return(MAXINT);
	}
	return(strncmp((char *) src1, (char *) src2, n));
}

WIN32DLL_DEFINE
long
mutils_strtol(__const mutils_word8 *nptr, mutils_word8 **endptr, const __const mutils_word8 base)
{
	return(strtol((char *) nptr, (char **) endptr, (int) base));
}

WIN32DLL_DEFINE
mutils_word8
mutils_val2char(__const mutils_word8 x)
{
	mutils_word8 out;
	static mutils_word8 *table = "0123456789abcdef";

	out = *(table + x);

	return(out);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_asciify(__const mutils_word8 *in, __const mutils_word32 len)
{
	mutils_word8 *ptrIn = (mutils_word8 *) in;
	mutils_word8 *buffer = mutils_malloc((2 * len) + 1);
	mutils_word8 *ptrOut = buffer;
	mutils_word32 loop;

	for (loop = 0; loop < len; loop++, ptrIn++)
	{
		*ptrOut++ = mutils_val2char((*ptrIn & 0xf0) >> 4);
		*ptrOut++ = mutils_val2char((*ptrIn & 0x0f));
	}
	return(buffer);
}

WIN32DLL_DEFINE
mutils_boolean
mutils_thequals(__const mutils_word8 *text, __const mutils_word8 *hash, __const mutils_word32 len)
{
	mutils_word8  *ptrText = (mutils_word8 *) text;
	mutils_word8  *ptrHash = (mutils_word8 *) hash;
	mutils_word32  loop;
	mutils_word8   temp;
	mutils_boolean equals;

	for (loop = 0; loop < len; loop++, ptrHash++)
	{
		if (mutils_val2char((*ptrHash & 0xf0) >> 4) != *ptrText++)
		{
			return(MUTILS_FALSE);
		}
		if (mutils_val2char((*ptrHash & 0x0f)) != *ptrText++)
		{
			return(MUTILS_FALSE);
		}
	}
	return(MUTILS_TRUE);
}
