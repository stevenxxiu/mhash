#!/usr/bin/python
import unittest

# Add build directory to search path
import os
if os.path.exists("build"):
	from distutils.util import get_platform
	import sys
	s = "build/lib.%s-%.3s" % (get_platform(), sys.version)
	s = os.path.join(os.getcwd(), s)
	sys.path.insert(0,s)

from mhash import *

class TestMHASH(unittest.TestCase):
	"Test MHASH class."

	DATA = [
			(MHASH_MD5,
			 ["this is a test phrase"],
			 "71f89553d9ad6b512659cac8f25f4732",
			 "q\xf8\x95S\xd9\xadkQ&Y\xca\xc8\xf2_G2"),
			(MHASH_MD5,
			 ["this is a test phrase", "this is a second test phrase"],
			 "a9a49032a2ab83d50d3945ea9670ebc0",
		     "\xa9\xa4\x902\xa2\xab\x83\xd5\r9E\xea\x96p\xeb\xc0"),
		   ]

	def testInitWithoutArgs(self):
		"Init should raise TypeError if called without arguments"
		self.assertRaises(TypeError, MHASH)
	
	def testInitWithInvalidHash(self):
		"Init should raise ValueError if called with an invalid hash"
		self.assertRaises(ValueError, MHASH, 1000)
	
	def testInit(self):
		"Try to create valid objects with every algorithm"
		for name, value in locals().items():
			if name[:6] == "MHASH_":
				m = MHASH(value)
	
	def testHexDigest(self):
		"Test hexdigest() with some predefined data"
		for type, strings, hexdigest, digest in self.DATA:
			m = MHASH(type)
			for s in strings:
				m.update(s)
			self.assertEqual(m.hexdigest(), hexdigest)

	def testDigest(self):
		"Test digest() with some predefined data"
		for type, strings, hexdigest, digest in self.DATA:
			m = MHASH(type)
			for s in strings:
				m.update(s)
			self.assertEqual(m.digest(), digest)

	def testInitHexDigest(self):
		"Test hexdigest() using init with some predefined data"
		for type, strings, hexdigest, digest in self.DATA:
			m = MHASH(type, "".join(strings))
			self.assertEqual(m.hexdigest(), hexdigest)

	def testInitDigest(self):
		"Test digest() using init with some predefined data"
		for type, strings, hexdigest, digest in self.DATA:
			m = MHASH(type, "".join(strings))
			self.assertEqual(m.digest(), digest)
			
	def testSubclass(self):
		"Test subclassing MHASH"
		class MyMHASH(MHASH):
			def __init__(self, type):
				MHASH.__init__(self, type)
			def update(self, str):
				MHASH.update(self, str)
			def digest(self):
				return MHASH.digest(self)
			def hexdigest(self):
				return MHASH.hexdigest(self)
		for type, strings, hexdigest, digest in self.DATA:
			m = MyMHASH(type)
			for s in strings:
				m.update(s)
			self.assertEqual(m.hexdigest(), hexdigest)
			self.assertEqual(m.digest(), digest)
			
class TestHMAC(unittest.TestCase):
	"Test HMAC class."

	DATA = [
			(MHASH_SHA1, "password",
			 ["this is a test phrase"],
			 "e0ac4d6e7dfce923658b1aa2ff7a99ab70cf572b",
			 "\xe0\xacMn}\xfc\xe9#e\x8b\x1a\xa2\xffz\x99\xabp\xcfW+"),
			(MHASH_SHA1, "password",
			 ["this is a test phrase", "this is a second test phrase"],
			 "8498ce21a4739b22d88a85f4189070e4c8f243b7",
			 "\x84\x98\xce!\xa4s\x9b\"\xd8\x8a\x85\xf4\x18\x90p\xe4\xc8\xf2C\xb7"),
		   ]

	def testInitWithoutArgs(self):
		"Init should raise TypeError if called without arguments"
		self.assertRaises(TypeError, HMAC)
	
	def testInitWithInvalidHash(self):
		"Init should raise ValueError if called with an invalid hash"
		self.assertRaises(ValueError, HMAC, 1000, "password")
	
	def testInit(self):
		"Try to create valid objects with every algorithm"
		for name, value in locals().items():
			if name[:6] == "MHASH_":
				m = HMAC(value, "password")
	
	def testHexDigest(self):
		"Test hexdigest() with some predefined data"
		for type, password, strings, hexdigest, digest in self.DATA:
			m = HMAC(type, password)
			for s in strings:
				m.update(s)
			self.assertEqual(m.hexdigest(), hexdigest)

	def testDigest(self):
		"Test digest() with some predefined data"
		for type, password, strings, hexdigest, digest in self.DATA:
			m = HMAC(type, password)
			for s in strings:
				m.update(s)
			self.assertEqual(m.digest(), digest)

	def testInitHexDigest(self):
		"Test hexdigest() using init with some predefined data"
		for type, password, strings, hexdigest, digest in self.DATA:
			m = HMAC(type, password, "".join(strings))
			self.assertEqual(m.hexdigest(), hexdigest)

	def testInitDigest(self):
		"Test digest() using init with some predefined data"
		for type, password, strings, hexdigest, digest in self.DATA:
			m = HMAC(type, password, "".join(strings))
			self.assertEqual(m.digest(), digest)
			
	def testSubclass(self):
		"Test subclassing HMAC"
		class MyHMAC(HMAC):
			def __init__(self, type, password):
				HMAC.__init__(self, type, password)
			def update(self, str):
				HMAC.update(self, str)
			def digest(self):
				return HMAC.digest(self)
			def hexdigest(self):
				return HMAC.hexdigest(self)
		for type, password, strings, hexdigest, digest in self.DATA:
			m = MyHMAC(type, password)
			for s in strings:
				m.update(s)
			self.assertEqual(m.hexdigest(), hexdigest)
			self.assertEqual(m.digest(), digest)

class TestHashFunctions(unittest.TestCase):
	"Testcase for hash functions."

	def testHashName(self):
		"Test hash_name() function"
		for name, value in globals().items():
			if name[:6] == "MHASH_":
				# This seem to be the rule so far
				self.assertEqual(hash_name(value), name[6:])

class TestKeygenFunctions(unittest.TestCase):
	"Testcase for keygen functions."

	DATA = [
			((KEYGEN_MCRYPT, "password", 10),
			 "_M\xcc;Z\xa7e\xd6\x1d\x83"),
			((KEYGEN_MCRYPT, "password", 20, MHASH_SHA1),
			 "[\xaaa\xe4\xc9\xb9??\x06\x82%\x0bl\xf83\x1b~\xe6\x8f\xd8"),
			((KEYGEN_S2K_ISALTED, "password", 15, MHASH_SHA256, "12345678", 17),
             "27A\xf7\t\xf4\x18M\x8b\xb5\x01\xebJb\xe0"),
		   ]
	
	SALTSIZE = [(KEYGEN_MCRYPT, 0),
				(KEYGEN_S2K_SALTED, 8),
				(KEYGEN_S2K_ISALTED, 8)]
	
	def testKeygen(self):
		"Generate some known keys"
		for args, result in self.DATA:
			self.assertEqual(keygen(*args), result)
	
	def testKeygenNoArguments(self):
		"Function keygen raises TypeError when not using enough arguments"
		args = (KEYGEN_MCRYPT, "password")
		self.assertRaises(TypeError, keygen, *args)
		
	def testKeygenSmallSalt(self):
		"Function keygen raises ValueError when salt is smaller than expected"
		args = (KEYGEN_S2K_SALTED, "password", 10, MHASH_SHA1, "1234567")
		self.assertRaises(ValueError, keygen, *args)
		
	def testKeygenWithEveryKeygenid(self):
		"Try to create a key with every keygenid and hashid"
		password = "mypassword"
		keysize = 10
		for name, keygenid in globals().items():
			if name[:7] == "KEYGEN_":
				salt = "x"*keygen_salt_size(keygenid)
				for name, hashid in globals().items():
					if name[:6] == "MHASH_":
						key = keygen(keygenid, password, keysize, hashid, salt)
						self.assertEqual(len(key), keysize)
				
	def testKeygenName(self):
		"Test keygen_name() function"
		for name, value in globals().items():
			if name[:7] == "KEYGEN_":
				# This seem to be the rule so far
				self.assertEqual(keygen_name(value), name[7:])
	
	def testUsesCount(self):
		"Test keygen_uses_count() function"
		self.assertEqual(keygen_uses_count(KEYGEN_S2K_ISALTED), 1)

	def testUsesHash(self):
		"Test keygen_uses_hashid() function"
		self.assertEqual(keygen_uses_hashid(KEYGEN_MCRYPT), 1)

	def testUsesSalt(self):
		"Test keygen_uses_count() function"
		self.assertEqual(keygen_uses_salt(KEYGEN_S2K_ISALTED), 1)

	def testSaltSize(self):
		"Test keygen_salt_size() function"
		for keygenid, saltsize in self.SALTSIZE:
			self.assertEqual(keygen_salt_size(keygenid), saltsize)

	def testMaxKeySize(self):
		"Test keygen_max_key_size() function"
		self.assertEqual(keygen_max_key_size(KEYGEN_MCRYPT), 0)

if __name__ == "__main__":
	unittest.main()

# vim:ts=4:sw=4
