/* MD2.H - header file for MD2C.C
 * $Id: mhash_md2.h,v 1.1 2000/04/03 14:03:57 nikos Exp $
 */

/* Copyright (C) 1990-2, RSA Data Security, Inc. Created 1990. All
   rights reserved.

   License to copy and use this software is granted for
   non-commercial Internet Privacy-Enhanced Mail provided that it is
   identified as the "RSA Data Security, Inc. MD2 Message Digest
   Algorithm" in all material mentioning or referencing this software
   or this function.

   RSA Data Security, Inc. makes no representations concerning either
   the merchantability of this software or the suitability of this
   software for any particular purpose. It is provided "as is"
   without express or implied warranty of any kind.

   These notices must be retained in any copies of any part of this
   documentation and/or software.
 */

#ifndef MHASH_MD2_H
#define MHASH_MD2_H

#include <libdefs.h>

#define MD2Init 		mhash_md2_init
#define MD2Update 		mhash_md2_update
#define MD2Final 		mhash_md2_final

#define MD2_HASHBYTES 16

typedef struct MD2Context {
  unsigned char state[16];	/* state */
  unsigned char checksum[16];	/* checksum */
  unsigned int count;		/* number of bytes, modulo 16 */
  unsigned char buffer[16];	/* input buffer */
} MD2_CTX;

void   MD2Init(MD2_CTX *);
void   MD2Update(MD2_CTX *, const unsigned char *, unsigned int);
void   MD2Final(unsigned char [MD2_HASHBYTES], MD2_CTX *);

#endif /* _MD2_H_ */
