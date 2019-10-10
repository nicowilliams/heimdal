include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = simple_csr_authorizer.la ipc_csr_authorizer.la
simple_csr_authorizer_la_SOURCES = simple_csr_authorizer.c
simple_csr_authorizer_la_LDFLAGS = -module
ipc_csr_authorizer_la_SOURCES = ipc_csr_authorizer.c
ipc_csr_authorizer_la_LDFLAGS = -module	\
				$(top_builddir)/lib/krb5/libkrb5.la \
				$(top_builddir)/lib/hx509/libhx509.la \
				$(top_builddir)/lib/ipc/libheim-ipcc.la \
				$(top_builddir)/lib/roken/libroken.la

CLEANFILES= 
EXTRA_DIST= NTMakefile
