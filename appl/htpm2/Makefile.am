include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += $(INCLUDE_openssl_crypto) \
	-I$(top_srcdir)/lib/htpm2 \
	-I$(top_srcdir)/lib/base

bin_PROGRAMS = htpm2tool

htpm2tool_SOURCES = htpm2tool.c

htpm2tool_LDADD = \
	$(top_builddir)/lib/htpm2/libhtpm2.la \
	$(top_builddir)/lib/hx509/libhx509.la \
	$(top_builddir)/lib/base/libheimbase.la \
	$(LIB_openssl_crypto) \
	$(LIB_sqlite3) \
	$(LIBADD_roken)

man_MANS = htpm2tool.1
EXTRA_DIST = htpm2tool.1
