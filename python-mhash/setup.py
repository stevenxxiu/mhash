#!/usr/bin/python
from distutils.core import setup, Extension

VERSION = "1.2"

setup(name="python-mhash",
      version = VERSION,
      description = "Python interface to mhash library",
      author = "Gustavo Niemeyer",
      author_email = "niemeyer@conectiva.com",
      license = "LGPL",
      url = "http://mhash.sourceforge.net",
      long_description = \
"""
Python interface for mhash library.

The mhash library provides a uniform interface to a large number of
hash algorithms. These algorithms can be used to compute checksums,
message digests, and other signatures. The HMAC support implements the
basics for message authentication, following RFC 2104.
""",
      ext_modules = [Extension("mhash",
      			       ["mhash.c"],
			       libraries=["mhash"],
			       define_macros=[("VERSION", '"%s"'%VERSION)])],
      )
