#AUTOMAKE_OPTIONS = foreign
SUBDIRS = lib doc src
EXTRA_DIST = mhash.spec.in mhash.spec

dist-hook:
	find $(distdir) -name CVS -o -name .cvsignore | xargs rm -rf
