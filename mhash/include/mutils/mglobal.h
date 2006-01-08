/*
 *    Copyright (C) 2005 Jonathan Day, Nikos Mavroyanopoulos
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


#if !defined(__MGLOBAL_H)
#define __MGLOBAL_H

typedef enum __hashid {
	MHASH_CRC32	=  0,
	MHASH_MD5	=  1,
	MHASH_SHA1	=  2,
	MHASH_HAVAL256	=  3,
	MHASH_RIPEMD160	=  5,
	MHASH_TIGER	=  7,
	MHASH_GOST	=  8,
	MHASH_CRC32B	=  9,
	MHASH_HAVAL224	= 10,
	MHASH_HAVAL192	= 11,
	MHASH_HAVAL160	= 12,
	MHASH_HAVAL128	= 13,
	MHASH_TIGER128	= 14,
	MHASH_TIGER160	= 15,
	MHASH_MD4	= 16,
	MHASH_SHA256	= 17,
	MHASH_ADLER32	= 18,
	MHASH_SHA224	= 19,
	MHASH_SHA512	= 20,
	MHASH_SHA384	= 21,
	MHASH_WHIRLPOOL	= 22,
	MHASH_RIPEMD128	= 23,
	MHASH_RIPEMD256	= 24,
	MHASH_RIPEMD320	= 25,
	MHASH_SNEFRU128	= 26,
	MHASH_SNEFRU256	= 27,
	MHASH_MD2	= 28,

	/*
	 * The following names and numbers are reserved for future use.
	 * The algorithms have NOT been implemented. The presence of a
	 * name on this list is NOT a guarantee of being implemented
	 * in a future version.

	 MHASH_AR		= 64,
	 MHASH_BOOGNISH		= 65,
	 MHASH_CELLHASH		= 66,
	 MHASH_FFT_HASH_I	= 67,
	 MHASH_FFT_HASH_II	= 68,
	 MHASH_NHASH		= 69,
	 MHASH_PANAMA		= 70,
	 MHASH_SMASH		= 71,
	 MHASH_SUBHASH		= 72,
	 
	 */
} hashid;

typedef enum __keygenid {
	KEYGEN_MCRYPT,		/* The key generator used in mcrypt */
	KEYGEN_ASIS,		/* Just returns the password as binary key */
	KEYGEN_HEX,		/* Just converts a hex key into a binary one */
	KEYGEN_PKDES,		/* The transformation used in Phil Karn's DES
				 * encryption program */
	KEYGEN_S2K_SIMPLE,	/* The OpenPGP (rfc2440) Simple S2K */
	KEYGEN_S2K_SALTED,	/* The OpenPGP Salted S2K */
	KEYGEN_S2K_ISALTED	/* The OpenPGP Iterated Salted S2K */
} __keygenid;


#endif
