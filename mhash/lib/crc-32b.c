/*
   CRC-32b version 1.03 by Craig Bruce, 27-Jan-94
   **
   **  Based on "File Verification Using CRC" by Mark R. Nelson in Dr. Dobb's
   **  Journal, May 1992, pp. 64-67.  This program DOES generate the same CRC
   **  values as ZMODEM and PKZIP
   **
   **  v1.00: original release.
   **  v1.01: fixed printf formats.
   **  v1.02: fixed something else.
   **  v1.03: replaced CRC constant table by generator function.
 */

#include "libdefs.h"
#include "mhash_crc32.h"

static word32 crcTable[256];

void
crc32b(word32 * crc, const void *buf, int len)
{
	const byte *p;

	for (p = buf; len > 0; ++p, --len)
		(*crc) = (((*crc) >> 8) & 0x00FFFFFF) ^ crcTable[(*crc ^ *p) & 0xff];
}

void
crc32bgen(void)
{
	word32 crc, poly;
	int i, j;

	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 8; j > 0; j--) {
			if (crc & 1) {
				crc = (crc >> 1) ^ poly;
			}
			else {
				crc >>= 1;
			}
		}
		crcTable[i] = crc;
	}
}
