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
 * This is a simple test driver for use in combination with test_hash.sh
 *
 * It's ugly, limited and you should hit :q! now
 *
 * $Id: driver.c,v 1.3 2001/07/12 15:34:06 nmav Exp $
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "../lib/mhash.h"

static const char hexconvtab[] = "0123456789ABCDEF";

/*
   Also used in PHP3 
 */

static char *
bin2hex(const unsigned char *old, const size_t oldlen, size_t * newlen)
{
	unsigned char *new = NULL;
	int i, j;

	new = (char *) malloc(oldlen * 2 * sizeof(char) + 1);
	if (!new)
		return (new);

	for (i = j = 0; i < oldlen; i++) {
		new[j++] = hexconvtab[old[i] >> 4];
		new[j++] = hexconvtab[old[i] & 15];
	}
	new[j] = '\0';

	if (newlen)
		*newlen = oldlen * 2 * sizeof(char);

	return (new);
}

int 
main(int argc, char **argv)
{
	size_t bsize;
	unsigned char data[128]; /* enough space to hold digests */
	size_t data_len;
	char *str;
	size_t str_len;
	hashid hashid;
	MHASH td;

	if (argc < 3)
		exit(1);

	hashid = atoi(argv[1]);
	data_len = atoi(argv[2]);

	if (mhash_get_hash_name(hashid)==NULL) 
		return 0;
	
	bsize = mhash_get_block_size(hashid);
	if (!bsize)
		exit(1);

	mhash_bzero(data, data_len + 1);
	

	if (data_len)
		read(0, data, data_len);

	td = mhash_init(hashid);
	mhash(td, data, data_len);
	
	mhash_deinit(td, data);
	str = bin2hex(data, bsize, &str_len);
	printf("%s\n", str);
	free(str);
	
	exit(0);
}
