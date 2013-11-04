# $Id$

KSH=/usr/bin/ksh

include $(top_srcdir)/Makefile.am.common

heimdal-depend:
        $(KSH) $(srcdir)/packages/solaris-svr4/depend.sh $(objdir)

heimdal.pkg: heimdal-depend
        $(KSH) $(srcdir)/packages/solaris-svr4/solaris.sh --pkgname heimdal --built $(objdir) 

all: heimdal.pkg
