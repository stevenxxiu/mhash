
mutils_error _mhash_gen_key_asis(void *keyword, mutils_word32 key_size,
				 mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_mcrypt(hashid algorithm,
				   void *keyword, mutils_word32 key_size,
				   void *salt, mutils_word32 salt_size,
				   mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_hex(void *keyword, mutils_word32 key_size,
				mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_s2k_simple(hashid algorithm,
				       void *keyword, mutils_word32 key_size,
				       mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_s2k_salted(hashid algorithm,
				       void *keyword, mutils_word32 key_size,
				       mutils_word8 *salt, mutils_word32 salt_size,
				       mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_s2k_isalted(hashid algorithm, mutils_word64 count,
					void *keyword, mutils_word32 key_size,
					mutils_word8 *salt, mutils_word32 salt_size,
					mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_pkdes(void *keyword, mutils_word32 key_size,
				  mutils_word8 *password, mutils_word32 plen);
mutils_error _mhash_gen_key_crypt(void *keyword, mutils_word32 key_size,
				  mutils_word8 *password, mutils_word32 plen,
				  void *salt, mutils_word32 salt_size);
mutils_error _mhash_gen_key_scrypt(void *keyword, mutils_word32 key_size,
				   mutils_word8 *password, mutils_word32 plen);
