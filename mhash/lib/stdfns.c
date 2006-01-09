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
   $Id: bzero.c,v 1.3 2004/05/02 20:03:10 imipak Exp $ 
 */

#include "libdefs.h"

/**
 * Some of these are wrappers. The idea is to eventually produce an extremely
 * lightweight set of robust, portable functions that are guaranteed to produce
 * a "safe" result, even with bogus inputs. We can't trust native C libraries
 * to validate inputs.
 */

WIN32DLL_DEFINE
void *
mutils_malloc(__const mutils_word32 n)
{
	void *ptr;

	if (n == 0)
	{
		return NULL;
	}

	ptr = malloc(n);

	if (ptr != NULL)
	{
		mutils_bzero(ptr, n);
	}

	return(ptr);
}

WIN32DLL_DEFINE
void
mutils_free(void *ptr)
{
	if (ptr == NULL)
	{
		return;
	}
	free(ptr);
	return;
}

WIN32DLL_DEFINE
void
mutils_bzero(void *s, __const mutils_word32 n)
{
	mutils_word8 *stmp = (mutils_word8 *) s;
	mutils_word32 i;

	if ((s == NULL) || (n == 0))
	{
		return;
	}

	for (i = 0; i < n; i++, stmp++)
	{
		*stmp = '\0';
	}
}

WIN32DLL_DEFINE
void
mutils_memset(void *s, __const mutils_word8 c, const mutils_word32 n)
{
	mutils_word8 *stmp = (mutils_word8 *) s;
	mutils_word32 i;

	if ((s == NULL) || (n == 0))
	{
		return;
	}


	for (i = 0; i < n; i++, stmp++)
	{
		*stmp = c;
	}
}

WIN32DLL_DEFINE
void
mutils_memcpy(void *dest, __const void *src, const mutils_word32 n)
{
	mutils_word8 *ptr1;
	mutils_word8 *ptr2;
	mutils_word32 i;

	if ((dest == NULL) || (src == NULL) || (n == 0))
	{
		return;
	}

	ptr1 = (mutils_word8 *) dest;
	ptr2 = (mutils_word8 *) src;

	for (i = 0; i < n; i++, ptr1++, ptr2++)
	{
		*ptr1 = *ptr2;
	}
}

#define MIX32(a) \
        (((mutils_word32)((mutils_word8 *)(a))[0]) | \
        (((mutils_word32)((mutils_word8 *)(a))[1]) << 8)| \
        (((mutils_word32)((mutils_word8 *)(a))[2]) << 16)| \
        (((mutils_word32)((mutils_word8 *)(a))[3]) << 24))

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
mutils_word32nswap(mutils_word32 *x, mutils_word32 n, mutils_boolean destructive)
{
	mutils_word32 loop;
	mutils_word32 *buffer;
	mutils_word32 *ptr;

	if (destructive == MUTILS_FALSE)
	{
		buffer = mutils_malloc(n * 4);
		if (buffer == NULL)
		{
			return(NULL);
		}
		mutils_memcpy(buffer, x, n * 4);
	}
	else
	{
		buffer = x;
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
void
mutils_memmove(void *dest, __const void *src, const mutils_word32 n)
{
	mutils_word8 *ptr1;
	mutils_word8 *ptr2;
	mutils_word32 i;

	if ((dest == NULL) || (src == NULL) || (n == 0))
	{
		return;
	}

	ptr1 = (mutils_word8 *) dest;
	ptr2 = (mutils_word8 *) src;

	for (i = 0; i < n; i++, ptr1++, ptr2++)
	{
		*ptr1 = *ptr2;
	}
}

WIN32DLL_DEFINE
int
mutils_memcmp(__const void *s1, const void *s2, const mutils_word32 n)
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
		ptr1 = (mutils_word8 *) str;
		ptr2 = ret;

		for (len = mutils_strlen(str); len > 0; len--, ptr1++, ptr2++)
		{
			*ptr2 = *ptr1;
		}
	}

	return(ret);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strcat(mutils_word8 *dest, __const mutils_word8 *src)
{
	if (dest == NULL)
	{
		return(NULL);
	}
	if (src == NULL)
	{
		return(dest);
	}
	return((mutils_word8 *) strcat((char *) dest, (char *) src));
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strcpy(mutils_word8 *dest, __const mutils_word8 *src)
{
	if (dest == NULL)
	{
		return(NULL);
	}
	return((mutils_word8 *) strcpy((char *) dest, (char *) src));
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_strncpy(mutils_word8 *dest, __const mutils_word8 *src, const mutils_word32 n)
{
	if (dest == NULL)
	{
		return(NULL);
	}
	if (n == 0)
	{
		return(NULL);
	}
	return((mutils_word8 *) strncpy((char *) dest, (char *) src, n));
}

WIN32DLL_DEFINE
int
mutils_strcmp(__const mutils_word8 *src1, const mutils_word8 *src2)
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
mutils_strncmp(__const mutils_word8 *src1, const mutils_word8 *src2, const mutils_word32 n)
{
	if (n == 0)
	{
		return(0);
	}
	if (src1 == NULL)
	{
		if (src2 = NULL)
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
mutils_strtol(__const mutils_word8 *nptr, mutils_word8 **endptr, const mutils_word8 base)
{
	return(strtol((char *) nptr, (char **) endptr, (int) base));
}

WIN32DLL_DEFINE
mutils_word8
mutils_val2char(mutils_word8 x)
{
	mutils_word8 out;

	switch(x)
	{
		case 0x0 : { out = '0'; break; }
		case 0x1 : { out = '1'; break; }
		case 0x2 : { out = '2'; break; }
		case 0x3 : { out = '3'; break; }
		case 0x4 : { out = '4'; break; }
		case 0x5 : { out = '5'; break; }
		case 0x6 : { out = '6'; break; }
		case 0x7 : { out = '7'; break; }
		case 0x8 : { out = '8'; break; }
		case 0x9 : { out = '9'; break; }
		case 0xa : { out = 'a'; break; }
		case 0xb : { out = 'b'; break; }
		case 0xc : { out = 'c'; break; }
		case 0xd : { out = 'd'; break; }
		case 0xe : { out = 'e'; break; }
		case 0xf : { out = 'f'; break; }
	}
	return(out);
}

WIN32DLL_DEFINE
mutils_word8 *
mutils_asciify(mutils_word8 *in, __const mutils_word32 len)
{
	mutils_word8 *ptrIn = in;
	mutils_word8 *buffer = mutils_malloc((2 * len) + 1);
	mutils_word8 *ptrOut = buffer;
	mutils_word32 loop;
	mutils_word8  temp;

	for (loop = 0; loop < len; loop++, ptrIn++)
	{
		temp = (*ptrIn & 0xf0) >> 4;
		*ptrOut++ = mutils_val2char(temp);
		temp = (*ptrIn & 0x0f);
		*ptrOut++ = mutils_val2char(temp);
	}
	return(buffer);
}

