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


#include "libdefs.h"

#ifdef ENABLE_CRC32

#include "mhash_crc32.h"

/** This polynomial ( 0xEDB88320L) DOES generate the same CRC values as ZMODEM and PKZIP
 */
static __const mutils_word32 crc32_table_b[256] =
{
	0x0UL, 0x77073096UL, 0xEE0E612CUL, 0x990951BAUL, 0x76DC419UL,
	0x706AF48FUL, 0xE963A535UL, 0x9E6495A3UL, 0xEDB8832UL, 0x79DCB8A4UL,
	0xE0D5E91EUL, 0x97D2D988UL, 0x9B64C2BUL, 0x7EB17CBDUL, 0xE7B82D07UL,
	0x90BF1D91UL, 0x1DB71064UL, 0x6AB020F2UL, 0xF3B97148UL, 0x84BE41DEUL,
	0x1ADAD47DUL, 0x6DDDE4EBUL, 0xF4D4B551UL, 0x83D385C7UL, 0x136C9856UL,
	0x646BA8C0UL, 0xFD62F97AUL, 0x8A65C9ECUL, 0x14015C4FUL, 0x63066CD9UL,
	0xFA0F3D63UL, 0x8D080DF5UL, 0x3B6E20C8UL, 0x4C69105EUL, 0xD56041E4UL,
	0xA2677172UL, 0x3C03E4D1UL, 0x4B04D447UL, 0xD20D85FDUL, 0xA50AB56BUL,
	0x35B5A8FAUL, 0x42B2986CUL, 0xDBBBC9D6UL, 0xACBCF940UL, 0x32D86CE3UL,
	0x45DF5C75UL, 0xDCD60DCFUL, 0xABD13D59UL, 0x26D930ACUL, 0x51DE003AUL,
	0xC8D75180UL, 0xBFD06116UL, 0x21B4F4B5UL, 0x56B3C423UL, 0xCFBA9599UL,
	0xB8BDA50FUL, 0x2802B89EUL, 0x5F058808UL, 0xC60CD9B2UL, 0xB10BE924UL,
	0x2F6F7C87UL, 0x58684C11UL, 0xC1611DABUL, 0xB6662D3DUL, 0x76DC4190UL,
	0x1DB7106UL, 0x98D220BCUL, 0xEFD5102AUL, 0x71B18589UL, 0x6B6B51FUL,
	0x9FBFE4A5UL, 0xE8B8D433UL, 0x7807C9A2UL, 0xF00F934UL, 0x9609A88EUL,
	0xE10E9818UL, 0x7F6A0DBBUL, 0x86D3D2DUL, 0x91646C97UL, 0xE6635C01UL,
	0x6B6B51F4UL, 0x1C6C6162UL, 0x856530D8UL, 0xF262004EUL, 0x6C0695EDUL,
	0x1B01A57BUL, 0x8208F4C1UL, 0xF50FC457UL, 0x65B0D9C6UL, 0x12B7E950UL,
	0x8BBEB8EAUL, 0xFCB9887CUL, 0x62DD1DDFUL, 0x15DA2D49UL, 0x8CD37CF3UL,
	0xFBD44C65UL, 0x4DB26158UL, 0x3AB551CEUL, 0xA3BC0074UL, 0xD4BB30E2UL,
	0x4ADFA541UL, 0x3DD895D7UL, 0xA4D1C46DUL, 0xD3D6F4FBUL, 0x4369E96AUL,
	0x346ED9FCUL, 0xAD678846UL, 0xDA60B8D0UL, 0x44042D73UL, 0x33031DE5UL,
	0xAA0A4C5FUL, 0xDD0D7CC9UL, 0x5005713CUL, 0x270241AAUL, 0xBE0B1010UL,
	0xC90C2086UL, 0x5768B525UL, 0x206F85B3UL, 0xB966D409UL, 0xCE61E49FUL,
	0x5EDEF90EUL, 0x29D9C998UL, 0xB0D09822UL, 0xC7D7A8B4UL, 0x59B33D17UL,
	0x2EB40D81UL, 0xB7BD5C3BUL, 0xC0BA6CADUL, 0xEDB88320UL, 0x9ABFB3B6UL,
	0x3B6E20CUL, 0x74B1D29AUL, 0xEAD54739UL, 0x9DD277AFUL, 0x4DB2615UL,
	0x73DC1683UL, 0xE3630B12UL, 0x94643B84UL, 0xD6D6A3EUL, 0x7A6A5AA8UL,
	0xE40ECF0BUL, 0x9309FF9DUL, 0xA00AE27UL, 0x7D079EB1UL, 0xF00F9344UL,
	0x8708A3D2UL, 0x1E01F268UL, 0x6906C2FEUL, 0xF762575DUL, 0x806567CBUL,
	0x196C3671UL, 0x6E6B06E7UL, 0xFED41B76UL, 0x89D32BE0UL, 0x10DA7A5AUL,
	0x67DD4ACCUL, 0xF9B9DF6FUL, 0x8EBEEFF9UL, 0x17B7BE43UL, 0x60B08ED5UL,
	0xD6D6A3E8UL, 0xA1D1937EUL, 0x38D8C2C4UL, 0x4FDFF252UL, 0xD1BB67F1UL,
	0xA6BC5767UL, 0x3FB506DDUL, 0x48B2364BUL, 0xD80D2BDAUL, 0xAF0A1B4CUL,
	0x36034AF6UL, 0x41047A60UL, 0xDF60EFC3UL, 0xA867DF55UL, 0x316E8EEFUL,
	0x4669BE79UL, 0xCB61B38CUL, 0xBC66831AUL, 0x256FD2A0UL, 0x5268E236UL,
	0xCC0C7795UL, 0xBB0B4703UL, 0x220216B9UL, 0x5505262FUL, 0xC5BA3BBEUL,
	0xB2BD0B28UL, 0x2BB45A92UL, 0x5CB36A04UL, 0xC2D7FFA7UL, 0xB5D0CF31UL,
	0x2CD99E8BUL, 0x5BDEAE1DUL, 0x9B64C2B0UL, 0xEC63F226UL, 0x756AA39CUL,
	0x26D930AUL, 0x9C0906A9UL, 0xEB0E363FUL, 0x72076785UL, 0x5005713UL,
	0x95BF4A82UL, 0xE2B87A14UL, 0x7BB12BAEUL, 0xCB61B38UL, 0x92D28E9BUL,
	0xE5D5BE0DUL, 0x7CDCEFB7UL, 0xBDBDF21UL, 0x86D3D2D4UL, 0xF1D4E242UL,
	0x68DDB3F8UL, 0x1FDA836EUL, 0x81BE16CDUL, 0xF6B9265BUL, 0x6FB077E1UL,
	0x18B74777UL, 0x88085AE6UL, 0xFF0F6A70UL, 0x66063BCAUL, 0x11010B5CUL,
	0x8F659EFFUL, 0xF862AE69UL, 0x616BFFD3UL, 0x166CCF45UL, 0xA00AE278UL,
	0xD70DD2EEUL, 0x4E048354UL, 0x3903B3C2UL, 0xA7672661UL, 0xD06016F7UL,
	0x4969474DUL, 0x3E6E77DBUL, 0xAED16A4AUL, 0xD9D65ADCUL, 0x40DF0B66UL,
	0x37D83BF0UL, 0xA9BCAE53UL, 0xDEBB9EC5UL, 0x47B2CF7FUL, 0x30B5FFE9UL,
	0xBDBDF21CUL, 0xCABAC28AUL, 0x53B39330UL, 0x24B4A3A6UL, 0xBAD03605UL,
	0xCDD70693UL, 0x54DE5729UL, 0x23D967BFUL, 0xB3667A2EUL, 0xC4614AB8UL,
	0x5D681B02UL, 0x2A6F2B94UL, 0xB40BBE37UL, 0xC30C8EA1UL, 0x5A05DF1BUL,
	0x2D02EF8DUL
};


/** This polynomial (0x04c11db7) is used at: AUTODIN II, Ethernet, & FDDI 
 */

static __const mutils_word32 crc32_table[256] =
{

	0x00000000UL, 0x04c11db7UL, 0x09823b6eUL, 0x0d4326d9UL,
	0x130476dcUL, 0x17c56b6bUL, 0x1a864db2UL, 0x1e475005UL,
	0x2608edb8UL, 0x22c9f00fUL, 0x2f8ad6d6UL, 0x2b4bcb61UL,
	0x350c9b64UL, 0x31cd86d3UL, 0x3c8ea00aUL, 0x384fbdbdUL,
	0x4c11db70UL, 0x48d0c6c7UL, 0x4593e01eUL, 0x4152fda9UL,
	0x5f15adacUL, 0x5bd4b01bUL, 0x569796c2UL, 0x52568b75UL,
	0x6a1936c8UL, 0x6ed82b7fUL, 0x639b0da6UL, 0x675a1011UL,
	0x791d4014UL, 0x7ddc5da3UL, 0x709f7b7aUL, 0x745e66cdUL,
	0x9823b6e0UL, 0x9ce2ab57UL, 0x91a18d8eUL, 0x95609039UL,
	0x8b27c03cUL, 0x8fe6dd8bUL, 0x82a5fb52UL, 0x8664e6e5UL,
	0xbe2b5b58UL, 0xbaea46efUL, 0xb7a96036UL, 0xb3687d81UL,
	0xad2f2d84UL, 0xa9ee3033UL, 0xa4ad16eaUL, 0xa06c0b5dUL,
	0xd4326d90UL, 0xd0f37027UL, 0xddb056feUL, 0xd9714b49UL,
	0xc7361b4cUL, 0xc3f706fbUL, 0xceb42022UL, 0xca753d95UL,
	0xf23a8028UL, 0xf6fb9d9fUL, 0xfbb8bb46UL, 0xff79a6f1UL,
	0xe13ef6f4UL, 0xe5ffeb43UL, 0xe8bccd9aUL, 0xec7dd02dUL,
	0x34867077UL, 0x30476dc0UL, 0x3d044b19UL, 0x39c556aeUL,
	0x278206abUL, 0x23431b1cUL, 0x2e003dc5UL, 0x2ac12072UL,
	0x128e9dcfUL, 0x164f8078UL, 0x1b0ca6a1UL, 0x1fcdbb16UL,
	0x018aeb13UL, 0x054bf6a4UL, 0x0808d07dUL, 0x0cc9cdcaUL,
	0x7897ab07UL, 0x7c56b6b0UL, 0x71159069UL, 0x75d48ddeUL,
	0x6b93dddbUL, 0x6f52c06cUL, 0x6211e6b5UL, 0x66d0fb02UL,
	0x5e9f46bfUL, 0x5a5e5b08UL, 0x571d7dd1UL, 0x53dc6066UL,
	0x4d9b3063UL, 0x495a2dd4UL, 0x44190b0dUL, 0x40d816baUL,
	0xaca5c697UL, 0xa864db20UL, 0xa527fdf9UL, 0xa1e6e04eUL,
	0xbfa1b04bUL, 0xbb60adfcUL, 0xb6238b25UL, 0xb2e29692UL,
	0x8aad2b2fUL, 0x8e6c3698UL, 0x832f1041UL, 0x87ee0df6UL,
	0x99a95df3UL, 0x9d684044UL, 0x902b669dUL, 0x94ea7b2aUL,
	0xe0b41de7UL, 0xe4750050UL, 0xe9362689UL, 0xedf73b3eUL,
	0xf3b06b3bUL, 0xf771768cUL, 0xfa325055UL, 0xfef34de2UL,
	0xc6bcf05fUL, 0xc27dede8UL, 0xcf3ecb31UL, 0xcbffd686UL,
	0xd5b88683UL, 0xd1799b34UL, 0xdc3abdedUL, 0xd8fba05aUL,
	0x690ce0eeUL, 0x6dcdfd59UL, 0x608edb80UL, 0x644fc637UL,
	0x7a089632UL, 0x7ec98b85UL, 0x738aad5cUL, 0x774bb0ebUL,
	0x4f040d56UL, 0x4bc510e1UL, 0x46863638UL, 0x42472b8fUL,
	0x5c007b8aUL, 0x58c1663dUL, 0x558240e4UL, 0x51435d53UL,
	0x251d3b9eUL, 0x21dc2629UL, 0x2c9f00f0UL, 0x285e1d47UL,
	0x36194d42UL, 0x32d850f5UL, 0x3f9b762cUL, 0x3b5a6b9bUL,
	0x0315d626UL, 0x07d4cb91UL, 0x0a97ed48UL, 0x0e56f0ffUL,
	0x1011a0faUL, 0x14d0bd4dUL, 0x19939b94UL, 0x1d528623UL,
	0xf12f560eUL, 0xf5ee4bb9UL, 0xf8ad6d60UL, 0xfc6c70d7UL,
	0xe22b20d2UL, 0xe6ea3d65UL, 0xeba91bbcUL, 0xef68060bUL,
	0xd727bbb6UL, 0xd3e6a601UL, 0xdea580d8UL, 0xda649d6fUL,
	0xc423cd6aUL, 0xc0e2d0ddUL, 0xcda1f604UL, 0xc960ebb3UL,
	0xbd3e8d7eUL, 0xb9ff90c9UL, 0xb4bcb610UL, 0xb07daba7UL,
	0xae3afba2UL, 0xaafbe615UL, 0xa7b8c0ccUL, 0xa379dd7bUL,
	0x9b3660c6UL, 0x9ff77d71UL, 0x92b45ba8UL, 0x9675461fUL,
	0x8832161aUL, 0x8cf30badUL, 0x81b02d74UL, 0x857130c3UL,
	0x5d8a9099UL, 0x594b8d2eUL, 0x5408abf7UL, 0x50c9b640UL,
	0x4e8ee645UL, 0x4a4ffbf2UL, 0x470cdd2bUL, 0x43cdc09cUL,
	0x7b827d21UL, 0x7f436096UL, 0x7200464fUL, 0x76c15bf8UL,
	0x68860bfdUL, 0x6c47164aUL, 0x61043093UL, 0x65c52d24UL,
	0x119b4be9UL, 0x155a565eUL, 0x18197087UL, 0x1cd86d30UL,
	0x029f3d35UL, 0x065e2082UL, 0x0b1d065bUL, 0x0fdc1becUL,
	0x3793a651UL, 0x3352bbe6UL, 0x3e119d3fUL, 0x3ad08088UL,
	0x2497d08dUL, 0x2056cd3aUL, 0x2d15ebe3UL, 0x29d4f654UL,
	0xc5a92679UL, 0xc1683bceUL, 0xcc2b1d17UL, 0xc8ea00a0UL,
	0xd6ad50a5UL, 0xd26c4d12UL, 0xdf2f6bcbUL, 0xdbee767cUL,
	0xe3a1cbc1UL, 0xe760d676UL, 0xea23f0afUL, 0xeee2ed18UL,
	0xf0a5bd1dUL, 0xf464a0aaUL, 0xf9278673UL, 0xfde69bc4UL,
	0x89b8fd09UL, 0x8d79e0beUL, 0x803ac667UL, 0x84fbdbd0UL,
	0x9abc8bd5UL, 0x9e7d9662UL, 0x933eb0bbUL, 0x97ffad0cUL,
	0xafb010b1UL, 0xab710d06UL, 0xa6322bdfUL, 0xa2f33668UL,
	0xbcb4666dUL, 0xb8757bdaUL, 0xb5365d03UL, 0xb1f740b4UL
};



void
mhash_clear_crc32(mutils_word32 *crc)
{
	*crc = 0xffffffff;			
/*
 * preload shift register, per CRC-32 spec 
 */
}

void
mhash_get_crc32(__const mutils_word32 *crc, void *ret)
{
	mutils_word32 tmp;
	tmp = ~(*crc);
	/*
	 * transmit complement, per CRC-32 spec 
	 */
#ifdef WORDS_BIGENDIAN
	tmp = mutils_word32swap(tmp);
#endif
	if (ret != NULL)
		mutils_memcpy(ret, &tmp, sizeof(mutils_word32));	
}

void
mhash_crc32(mutils_word32 *crc, __const void *given_buf, mutils_word32 len)
{
	__const mutils_word8 *p;

#if defined(MHASH_ROBUST)	
	if ((crc == NULL) || (given_buffer == NULL) || (len == 0))
		return;
#endif

	for (p = given_buf; len > 0; ++p, --len) {
		(*crc) = ((*crc) << 8) ^ crc32_table[((*crc) >> 24) ^ *p];
	}
}

void
mhash_crc32b(mutils_word32 *crc, __const void *buf, mutils_word32 len)
{
	__const mutils_word8 *p;

#if defined(MHASH_ROBUST)
	if ((crc == NULL) || (given_buffer == NULL) || (len == 0))
		return;
#endif

	for (p = buf; len > 0; ++p, --len)
		(*crc) = (((*crc) >> 8) & 0x00FFFFFF) ^ crc32_table_b[(*crc ^ *p) & 0xff];
}

#endif /* ENABLE_CRC32 */
