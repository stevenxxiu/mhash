#ifndef MHASH_CRC32_H
#define MHASH_CRC32_H

#include "libdefs.h"

#define clear_crc32 		mhash_clear_crc32
#define get_crc32			mhash_get_crc32
#define crc32				mhash_crc32
#define crc32b				mhash_crc32b
#define crc32bgen			mhash_crc32bgen

void clear_crc32(word32 * crc);
void get_crc32(void* ret, const word32 * crc);
void crc32(word32 * crc, const void *, int);
void crc32b(word32 * crc, const void *, int);
void crc32bgen(void);

#endif
