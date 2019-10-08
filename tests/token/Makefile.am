include $(top_srcdir)/Makefile.am.common

LDADD = -lcjwt

lib_LTLIBRARIES = cjwt_token_validator.la stub_token_validator.la
cjwt_token_validator_la_SOURCES = cjwt_token_validator.c
cjwt_token_validator_la_AM_CPPFLAGS = $(CJWT_FLAGS)
cjwt_token_validator_la_LDFLAGS = -module $(CJWT_LIBS)
stub_token_validator_la_SOURCES = stub_token_validator.c
stub_token_validator_la_LDFLAGS = -module

CLEANFILES= 
EXTRA_DIST= NTMakefile
