# $Id$

KSH=/usr/bin/ksh

include $(top_srcdir)/Makefile.am.common

heimdal.pkg:
	env ENV= $(KSH) $(srcdir)/solaris.sh --pkgname heimdal --built $(top_builddir) \
		-- --prefix=$(prefix)

all: heimdal.pkg
