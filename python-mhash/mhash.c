/*

python-mhash - python mhash library interface

Copyright (c) 2002  Gustavo Niemeyer <niemeyer@conectiva.com>

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

#include <mhash.h>

/* Fixes a stupid warning */

#if defined(_POSIX_C_SOURCE)
#undef _POSIX_C_SOURCE
#endif

#include "Python.h"
#include "structmember.h"

static char __author__[] =
"The mhash python module was developed by:\n\
\n\
    Gustavo Niemeyer <niemeyer@conectiva.com>\n\
";

typedef struct {
	PyObject_HEAD
	MHASH thread;
	hashid type;
	size_t digest_size;
	void *(*end)(MHASH thread); /* Allow subclassing. */
} MHASHObject;

#define OFF(x) offsetof(MHASHObject, x)

static PyMemberDef MHASH_members[] = {
	{"type",         T_INT,    OFF(type),         READONLY},
	{"digest_size",  T_INT,    OFF(digest_size), READONLY},
	{0}
};

staticforward PyTypeObject MHASH_Type;

#define MHASHObject_Check(v)	((v)->ob_type == &MHASH_Type)

static void
MHASH_dealloc(MHASHObject *self)
{
	if (self->thread) {
		void *ret = mhash_end(self->thread);
		if (ret) free(ret);
	}
	self->ob_type->tp_free((PyObject *)self);
}

static int valid_hash(hashid type)
{
	return(mhash_get_hash_name_static(type) != NULL);
}

static int
MHASH_init(MHASHObject *self, PyObject *args)
{
	hashid type;
	void *plaintext = NULL;
	size_t size;
	if (!PyArg_ParseTuple(args, "i|s#:init", &type, &plaintext, &size))
		return -1;
	self->thread = mhash_init(type);
	if (self->thread == MHASH_FAILED) {
		if (!valid_hash(type))
			PyErr_SetString(PyExc_ValueError, "invalid hash type");
		else
			PyErr_SetString(PyExc_Exception, "unknown mhash error");
		return -1;
	}
	if (plaintext)
		mhash(self->thread, plaintext, size);
	self->type = type;
	self->digest_size = mhash_get_block_size(type);
	self->end = mhash_end;
	return 0;
}

static PyObject *
MHASH_update(MHASHObject *self, PyObject *args)
{
	void *plaintext;
	size_t size;

	if (!PyArg_ParseTuple(args, "s#:update", &plaintext, &size))
		return NULL;

	mhash(self->thread, plaintext, size);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
MHASH_digest(MHASHObject *self, PyObject *args)
{
	MHASH thread;
	void *digest;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, ":digest"))
		return NULL;
	thread = mhash_cp(self->thread);
	digest = self->end(thread);
	ret = PyString_FromStringAndSize((char*)digest, self->digest_size);
	free(digest);
	return ret;
}

static PyObject *
MHASH_hexdigest(MHASHObject *self, PyObject *args)
{
	MHASH thread;
	unsigned char *digest;
	unsigned char *hexdigest;
	register int i,j;
	char *hextable = "0123456789abcdef";
	PyObject *ret;
	if (!PyArg_ParseTuple(args, ":hexdigest"))
		return NULL;
	thread = mhash_cp(self->thread);
	digest = self->end(thread);
	hexdigest = PyMem_Malloc(self->digest_size*2);
	for(i=j=0; i<self->digest_size; i++) {
		hexdigest[j++] = hextable[digest[i] >> 4];
		hexdigest[j++] = hextable[digest[i] & 0xf];
	}
	ret = PyString_FromStringAndSize((char*)hexdigest,
					 self->digest_size*2);
	free(digest);
	PyMem_Free(hexdigest);
	return ret;
}

static PyObject *
MHASH_copy(MHASHObject *self, PyObject *args)
{
	MHASHObject *obj;
	if (!PyArg_ParseTuple(args, ":copy"))
		return NULL;
	obj = PyObject_New(MHASHObject, &MHASH_Type);
	if (self == NULL)
		return NULL;
	obj->thread = mhash_cp(self->thread);
	if (self->thread == MHASH_FAILED) {
		PyObject_Del(obj);
		PyErr_SetString(PyExc_Exception, "unknown mhash error");
		return NULL;
	}
	obj->type = self->type;
	obj->digest_size = self->digest_size;
	return (PyObject *)obj;
}

static PyMethodDef MHASH_methods[] = {
	{"update",	(PyCFunction)MHASH_update,	METH_VARARGS},
	{"digest",	(PyCFunction)MHASH_digest,	METH_VARARGS},
	{"hexdigest",	(PyCFunction)MHASH_hexdigest,	METH_VARARGS},
	{"copy",	(PyCFunction)MHASH_copy,	METH_VARARGS},
	{NULL,		NULL}		/* sentinel */
};

static char MHASH__doc__[] = \
"This is the base class, offering basic hashing functionality. MHASH is\n \
implmented as a newstyle class. It means you may subclass it in your\n \
python programs and extend its functionality. Don't forget to call its\n \
__init__ method if you do this.\n \
\n \
Constructor:\n \
\n \
MHASH(algorithm [, string])\n \
\n \
The first parameter is one of the MHASH_* constants provided in the mhash\n \
module. This will select the hashing algorithm you want to use. The second\n \
is a string which will update the hash state. It's useful when you want a\n \
oneliner hash, such as the following:\n \
\n \
MHASH(MHASH_SHA1, \"My hashed string\").hexdigest()\n \
\n \
Methods:\n \
\n \
update(string)  - Update the hash state with 'string'.\n \
digest()        - Retrieve the currect digest.\n \
hexdigest()     - Retrieve the current digest in hex format.\n \
copy()          - Create a new MHASH object, copying the current state.\n \
\n \
Attributes:\n \
\n \
type            - Selected algorithm.\n \
digest_size     - Digest size of the selected algorithm.\
";

statichere PyTypeObject MHASH_Type = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"mhash.MHASH",		/*tp_name*/
	sizeof(MHASHObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	(destructor)MHASH_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
        0,                      /*tp_call*/
        0,                      /*tp_str*/
        PyObject_GenericGetAttr,/*tp_getattro*/
        PyObject_GenericSetAttr,/*tp_setattro*/
        0,                      /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        MHASH__doc__,           /*tp_doc*/
        0,                      /*tp_traverse*/
        0,                      /*tp_clear*/
        0,                      /*tp_richcompare*/
        0,                      /*tp_weaklistoffset*/
        0,                      /*tp_iter*/
        0,                      /*tp_iternext*/
        MHASH_methods,          /*tp_methods*/
        MHASH_members,          /*tp_members*/
        0,                      /*tp_getset*/
        0,                      /*tp_base*/
        0,                      /*tp_dict*/
        0,                      /*tp_descr_get*/
        0,                      /*tp_descr_set*/
        0,                      /*tp_dictoffset*/
        (initproc)MHASH_init,   /*tp_init*/
        PyType_GenericAlloc,    /*tp_alloc*/
        PyType_GenericNew,      /*tp_new*/
      	_PyObject_Del,       /*tp_free*/
        0,                      /*tp_is_gc*/
};
/* --------------------------------------------------------------------- */

static int
HMAC_init(MHASHObject *self, PyObject *args)
{
	hashid type;
	void *key;
	int key_size;
	void *plaintext = NULL;
	size_t size;
	if (!PyArg_ParseTuple(args, "is#|s#:init", &type, &key, &key_size,
						   &plaintext, &size))
		return -1;
	self->thread = mhash_hmac_init(type, key, key_size,
				       mhash_get_hash_pblock(type));
	if (self->thread == MHASH_FAILED) {
		if (!valid_hash(type))
			PyErr_SetString(PyExc_ValueError, "invalid hash type");
		else
			PyErr_SetString(PyExc_Exception, "unknown mhash error");
		return -1;
	}
	if (plaintext)
		mhash(self->thread, plaintext, size);
	self->type = type;
	self->digest_size = mhash_get_block_size(type);
	self->end = mhash_hmac_end;
	return 0;
}

static char HMAC__doc__[] =
"This class implements HMAC, a mechanism for message authentication\n\
using cryptographic hash functions, described in RFC2104. HMAC can\n\
be used to create message digests using a secret key, so that these\n\
message digests cannot be regenerated (or replaced) by someone else.\n\
\n\
HMAC is implemented as a newstyle class subclassing MHASH. It has the\n\
the same methods and the same attributes, differing only in the\n\
constructor, explained here:\n\
\n\
Constructor:\n\
\n\
HMAC(algorithm, password [, string])\n\
\n\
The first parameter is one of the MHASH_* constants provided in the mhash\n\
module, and will select the hashing algorithm you want to use. The second\n\
is the secret key you want to use in the digest, and the third is a\n\
string which will update the hash state. It's useful when you want a\n\
oneliner hash, such as the following:\n\
\n\
MHASH(MHASH_MD5, \"My secret key\", \"My hashed string\").hexdigest()\n\
";

statichere PyTypeObject HMAC_Type = {
	PyObject_HEAD_INIT(NULL)
	0,			/*ob_size*/
	"mhash.HMAC",		/*tp_name*/
	sizeof(MHASHObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	(destructor)MHASH_dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	0,			/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
        0,                      /*tp_call*/
        0,                      /*tp_str*/
        0,                      /*tp_getattro*/
        0,                      /*tp_setattro*/
        0,                      /*tp_as_buffer*/
        Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE, /*tp_flags*/
        HMAC__doc__,            /*tp_doc*/
        0,                      /*tp_traverse*/
        0,                      /*tp_clear*/
        0,                      /*tp_richcompare*/
        0,                      /*tp_weaklistoffset*/
        0,                      /*tp_iter*/
        0,                      /*tp_iternext*/
        0,                      /*tp_methods*/
        0,                      /*tp_members*/
        0,                      /*tp_getset*/
        0, /* &MHASH_Type, in the future */ /*tp_base*/
        0,                      /*tp_dict*/
        0,                      /*tp_descr_get*/
        0,                      /*tp_descr_set*/
        0,                      /*tp_dictoffset*/
        (initproc)HMAC_init,    /*tp_init*/
        0,                      /*tp_alloc*/
        0,                      /*tp_new*/
      	0,                      /*tp_free*/
        0,                      /*tp_is_gc*/
};
/* --------------------------------------------------------------------- */

static char hash_name__doc__[] =
"hash_name(hashid) -> name\n\
\n\
Returns name of hashid hash algorithm.\n\
";

static PyObject *
_mhash_hash_name(PyObject *self, PyObject *args)
{
	hashid type;
	char *name;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "i:hash_name", &type))
		return NULL;
	name = mhash_get_hash_name(type);
	ret = PyString_FromString(name);
	free(name);
	return ret;
}

static char keygen__doc__[] =
"keygen(keygenid,\n\
        password,\n\
        key_size,\n\
	hashid=MHASH_MD5,\n\
	salt=\"\",\n\
	count=0) -> key\n\
\n\
This function uses the algorithm specified in keygenid and the\n\
password to generate a key of key_size length. Depending on the\n\
algorithm you select, the parameters hashid, salt, and count are\n\
used. You may discover when they are used with the keygen_uses_*()\n\
functions. You may also check if the selected algorithm has any\n\
limitations about the key_size with keygen_max_key_size() function.\n\
Some algorithms using salt require an exact number of bytes in it,\n\
so it must not contain less bytes than this (more is allowed, and\n\
ignored). You may check the salt size using keygen_salt_size().\n\
";

static PyObject *
_mhash_keygen(PyObject *self, PyObject *args, PyObject *kwargs)
{
	keygenid keygen_algo;
	hashid hash_algo = MHASH_MD5;
	void *keyword;
	int key_size;
	void *salt = "";
	int salt_size = 0;
	unsigned char *password;
	int passlen;
	unsigned int count = 0;

	static char *kwlist[] = {"keygenid", "password", "key_size",
				 "hashid", "salt", "count", NULL};
	PyObject *ret;

	unsigned int algo_key_size;
	unsigned int algo_salt_size;
	
	if (!PyArg_ParseTupleAndKeywords(args, kwargs, "is#i|is#i:keygen",
				         kwlist, &keygen_algo,
					 &password, &passlen, &key_size,
					 &hash_algo, &salt, &salt_size, &count))
		return NULL;

	/* Do some sanity checks in the parameters. */
	algo_key_size = mhash_get_keygen_max_key_size(keygen_algo);
	if (algo_key_size != 0 && key_size > algo_key_size) {
		PyErr_Format(PyExc_ValueError, "key_size has exceeded the "
			     "maximum key_size of algorithm (%d)",
			     algo_key_size);
		return NULL;
	}
	algo_salt_size = mhash_get_keygen_salt_size(keygen_algo);
	if (salt_size < algo_salt_size) {
		PyErr_Format(PyExc_ValueError, "salt size is smaller than "
			     "the salt size used by the algorithm (%d)",
			     algo_salt_size);
		return NULL;
	}

	keyword = PyMem_Malloc(key_size);
	mhash_keygen(keygen_algo, hash_algo, count, keyword, key_size,
		     salt, salt_size, password, passlen);
	ret = PyString_FromStringAndSize(keyword, key_size);
	PyMem_Free(keyword);
	return ret;
}

static char keygen_name__doc__[] =
"keygen_name(keygenid) -> name\n\
\n\
Returns name of keygenid keygen algorithm.\n\
";

static PyObject *
_mhash_keygen_name(PyObject *self, PyObject *args)
{
	keygenid type;
	char *name;
	PyObject *ret;
	if (!PyArg_ParseTuple(args, "i:keygen_name", &type))
		return NULL;
	name = mhash_get_keygen_name(type);
	ret = PyString_FromString(name);
	free(name);
	return ret;
}

static char keygen_uses_hashid__doc__[] =
"keygen_uses_hashid(keygenid) -> bool\n\
\n\
Returns true if keygenid algorithm uses the hashid parameter of keygen().\n\
";

static PyObject *
_mhash_keygen_uses_hashid(PyObject *self, PyObject *args)
{
	keygenid type;
	if (!PyArg_ParseTuple(args, "i:keygen_uses_hashid", &type))
		return NULL;
	return PyInt_FromLong(mhash_keygen_uses_hash_algorithm(type));
}

static char keygen_uses_count__doc__[] =
"keygen_uses_count(keygenid) -> bool\n\
\n\
Returns true if keygenid algorithm uses the count parameter of keygen().\n\
";

static PyObject *
_mhash_keygen_uses_count(PyObject *self, PyObject *args)
{
	keygenid type;
	if (!PyArg_ParseTuple(args, "i:keygen_uses_count", &type))
		return NULL;
	return PyInt_FromLong(mhash_keygen_uses_count(type));
}

static char keygen_uses_salt__doc__[] =
"keygen_uses_salt(keygenid) -> bool\n\
\n\
Returns true if keygenid algorithm uses the salt parameter of keygen().\n\
You may want to check the keygen_salt_size() function.\n\
";

static PyObject *
_mhash_keygen_uses_salt(PyObject *self, PyObject *args)
{
	keygenid type;
	if (!PyArg_ParseTuple(args, "i:keygen_uses_salt", &type))
		return NULL;
	return PyInt_FromLong(mhash_keygen_uses_salt(type));
}

static char keygen_salt_size__doc__[] =
"keygen_salt_size(keygenid) -> size\n\
\n\
Returns the salt size needed by the keygenid algorithm. If the algorithm\n\
doesn't use the salt parameter, or if the salt may be of any size, it\n\
will return 0 instead. Note that you may provide a salt with more bytes\n\
than the required, but the extra bytes will be ignored.\n\
";

static PyObject *
_mhash_keygen_salt_size(PyObject *self, PyObject *args)
{
	keygenid type;
	if (!PyArg_ParseTuple(args, "i:keygen_salt_size", &type))
		return NULL;
	return PyInt_FromLong(mhash_get_keygen_salt_size(type));
}

static char keygen_max_key_size__doc__[] =
"keygen_max_key_size(keygenid) -> size\n\
\n\
Returns the maximum key size supported by the keygenid algorithm. Most\n\
of them (all?) don't have any limitations, but you may check if any\n\
algorithm has some using this function.\n\
";

static PyObject *
_mhash_keygen_max_key_size(PyObject *self, PyObject *args)
{
	keygenid type;
	if (!PyArg_ParseTuple(args, "i:keygen_max_key_size", &type))
		return NULL;
	return PyInt_FromLong(mhash_get_keygen_max_key_size(type));
}

/* List of functions defined in the module */

static PyMethodDef mhash_methods[] = {
	{"hash_name", _mhash_hash_name, METH_VARARGS,
		hash_name__doc__},
	{"keygen", (PyCFunction)_mhash_keygen, METH_VARARGS|METH_KEYWORDS,
		keygen__doc__},
	{"keygen_name", _mhash_keygen_name, METH_VARARGS,
		keygen_name__doc__},
	{"keygen_uses_hashid", _mhash_keygen_uses_hashid, METH_VARARGS,
		keygen_uses_hashid__doc__},
	{"keygen_uses_count", _mhash_keygen_uses_count, METH_VARARGS,
		keygen_uses_count__doc__},
	{"keygen_uses_salt", _mhash_keygen_uses_salt, METH_VARARGS,
		keygen_uses_salt__doc__},
	{"keygen_salt_size", _mhash_keygen_salt_size, METH_VARARGS,
		keygen_salt_size__doc__},
	{"keygen_max_key_size", _mhash_keygen_max_key_size, METH_VARARGS,
		keygen_max_key_size__doc__},
	{NULL,		NULL}		/* sentinel */
};


static char mhash__doc__[] =
"The mhash library provides an easy to use interface for several hash\n\
algorithms (also known as 'one-way' algorithms). These can be used to\n\
create checksums, message digests and more. Currently, MD5, SHA1, GOST,\n\
TIGER, RIPE- MD160, HAVAL and several other algorithms are supported.\n\
\n\
This module exports functionality provided by mhash to python programs.\n\
\n\
Classes:\n\
\n\
MHASH(algorithm [, string])\n\
HMAC(algorithm, password [, string])\n\
\n\
These are newstyle classes, and may be subclassed by python classes.\n\
\n\
Functions:\n\
\n\
hash_name(hashid)\n\
keygen(keygenid, password, key_size [, hashid, salt, count])\n\
keygen_name(keygenid)\n\
keygen_uses_hash(keygenid)\n\
keygen_uses_count(keygenid)\n\
keygen_uses_salt(keygenid)\n\
keygen_salt_size(keygenid)\n\
keygen_max_key_size(keygenid)\n\
\n\
Constants:\n\
\n\
MHASH_*\n\
KEYGEN_*\n\
";

DL_EXPORT(void)
initmhash(void)
{
	PyObject *m, *d;
	int res;

	MHASH_Type.ob_type = &PyType_Type;

	HMAC_Type.tp_base = &MHASH_Type;
	/* PyType_Ready() initializes ob_type to &PyType_Type if it's NULL */
	if (PyType_Ready(&HMAC_Type) < 0)
		return;

	m = Py_InitModule3("mhash", mhash_methods, mhash__doc__);
	d = PyModule_GetDict(m);
	Py_INCREF(&MHASH_Type);
	res = PyDict_SetItemString(d, "MHASH", (PyObject *)&MHASH_Type);
	Py_INCREF(&HMAC_Type);
	res = PyDict_SetItemString(d, "HMAC", (PyObject *)&HMAC_Type);
	res = PyDict_SetItemString(d, "__author__",
			     PyString_FromString(__author__));
	res = PyDict_SetItemString(d, "__version__",
			     PyString_FromString(VERSION));

#define INSINT(x) (void) PyModule_AddIntConstant(m, #x, x)

	/* Hash algorithms */
	INSINT(MHASH_CRC32);
	INSINT(MHASH_MD5);
	INSINT(MHASH_SHA1);
	INSINT(MHASH_HAVAL256);
	INSINT(MHASH_RIPEMD160);
	INSINT(MHASH_TIGER);
	INSINT(MHASH_GOST);
	INSINT(MHASH_CRC32B);
	INSINT(MHASH_HAVAL224);
	INSINT(MHASH_HAVAL192);
	INSINT(MHASH_HAVAL160);
	INSINT(MHASH_HAVAL128);
	INSINT(MHASH_TIGER128);
	INSINT(MHASH_TIGER160);
	INSINT(MHASH_MD4);
#if MHASH_API_VERSION >= 20011020
	INSINT(MHASH_SHA256);
	INSINT(MHASH_ADLER32);
#endif
#if MHASH_API_VERSION >= 20020524
	INSINT(MHASH_SHA224);
	INSINT(MHASH_SHA512);
	INSINT(MHASH_SHA384);
	INSINT(MHASH_WHIRLPOOL);
	INSINT(MHASH_RIPEMD128);
	INSINT(MHASH_RIPEMD256);
	INSINT(MHASH_RIPEMD320);
	INSINT(MHASH_SNEFRU128);
	INSINT(MHASH_SNEFRU256);
	INSINT(MHASH_MD2);
#endif

	/* Keygen algorithms */
	INSINT(KEYGEN_MCRYPT);
	INSINT(KEYGEN_ASIS);
	INSINT(KEYGEN_HEX);
	INSINT(KEYGEN_PKDES);
	INSINT(KEYGEN_S2K_SIMPLE);
	INSINT(KEYGEN_S2K_SALTED);
	INSINT(KEYGEN_S2K_ISALTED);
}
