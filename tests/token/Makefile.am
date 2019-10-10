include $(top_srcdir)/Makefile.am.common

LDADD = -lcjwt

noinst_PROGRAMS = token_validator
token_validator_SOURCES = token_validator.c
token_validator_LDADD = -ldl
token_validator_AM_CPPFLAGS = $(CJWT_FLAGS)

lib_LTLIBRARIES = cjwt_token_validator.la stub_token_validator.la
cjwt_token_validator_la_SOURCES = cjwt_token_validator.c
cjwt_token_validator_la_AM_CPPFLAGS = $(CJWT_FLAGS)
cjwt_token_validator_la_LDFLAGS = -module $(CJWT_LIBS)
stub_token_validator_la_SOURCES = stub_token_validator.c
stub_token_validator_la_LDFLAGS = -module

CLEANFILES= \
	server.keytab \
	current-db* \
	foopassword \
	krb5.conf krb5.conf.tmp \
	messages.log

EXTRA_DIST = \
	NTMakefile
