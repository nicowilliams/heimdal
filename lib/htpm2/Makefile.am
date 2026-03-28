include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += $(INCLUDE_openssl_crypto) -I$(top_srcdir)/lib/base

lib_LTLIBRARIES = libhtpm2.la
libhtpm2_la_LDFLAGS = -version-info 0:0:0

BUILT_SOURCES = \
	htpm2_err.c	\
	htpm2_err.h

dist_libhtpm2_la_SOURCES = \
	htpm2.h \
	htpm2_locl.h \
	result.c \
	context.c \
	crypto.c \
	crypto.h \
	marshal.c \
	marshal.h \
	transport.c \
	transport_device.c \
	transport_socket.c \
	transport_pipe.c \
	command.c \
	session.c \
	session_crypto.c \
	object.c \
	key_templates.c \
	create.c \
	load.c \
	import.c \
	evict.c \
	context_mgmt.c \
	sign.c \
	quote.c \
	certify.c \
	decrypt.c \
	credential.c \
	soft.c \
	encrypt_to.c \
	pcr.c \
	random.c \
	policy.c \
	error.c

libhtpm2_la_LIBADD = \
	$(LIB_com_err) \
	$(LIB_openssl_crypto) \
	$(top_builddir)/lib/base/libheimbase.la \
	$(LIBADD_roken)

if versionscript
libhtpm2_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif

libhtpm2_la_DEPENDENCIES = version-script.map
$(libhtpm2_la_OBJECTS): $(srcdir)/version-script.map

nodist_libhtpm2_la_SOURCES = $(BUILT_SOURCES)

dist_include_HEADERS = htpm2.h

bin_PROGRAMS = htpm2tool

htpm2tool_SOURCES = htpm2tool.c
htpm2tool_LDADD = libhtpm2.la $(LIB_openssl_crypto) \
	$(top_builddir)/lib/base/libheimbase.la $(LIBADD_roken)

nodist_include_HEADERS = htpm2_err.h

check_PROGRAMS = \
	test_result \
	test_crypto \
	test_swtpm

TESTS = \
	test_result \
	test_crypto \
	test_swtpm

test_result_SOURCES = test_result.c
test_result_LDADD = libhtpm2.la $(LIB_openssl_crypto) $(LIBADD_roken)

test_crypto_SOURCES = test_crypto.c
test_crypto_LDADD = libhtpm2.la $(LIB_openssl_crypto) $(LIBADD_roken)

test_swtpm_SOURCES = test_swtpm.c
test_swtpm_LDADD = libhtpm2.la $(LIB_openssl_crypto) \
	$(top_builddir)/lib/base/libheimbase.la $(LIBADD_roken)
