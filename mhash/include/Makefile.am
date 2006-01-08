#AUTOMAKE_OPTIONS = foreign

SUBDIRS = mutils

include_HEADERS = mhash.h

dist-hook:
	find $(distdir) -name CVS -o -name .cvsignore | xargs rm -rf
