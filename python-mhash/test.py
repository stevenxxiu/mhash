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

class TestFunctions(unittest.TestCase):
	"Testcase for general functions."

	def testHashName(self):
		"Test hash_name() function"
		for name, value in locals().items():
			if name[:6] == "MHASH_":
				# This seem to be the rule so far
				self.assertEqual(hash_name(value), name[6:])

if __name__ == "__main__":
	unittest.main()

# vim:ts=4:sw=4
