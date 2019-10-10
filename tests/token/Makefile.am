include $(top_srcdir)/Makefile.am.common

LDADD = -lcjwt

lib_LTLIBRARIES = cjwt_token_validator.la \
		  stub_token_validator.la \
		  negotiate_token_validator.la
cjwt_token_validator_la_SOURCES = cjwt_token_validator.c
cjwt_token_validator_la_AM_CPPFLAGS = $(CJSON_FLAGS) $(CJWT_FLAGS)
cjwt_token_validator_la_LDFLAGS = -module $(CJSON_LIBS) $(CJWT_LIBS)
stub_token_validator_la_SOURCES = stub_token_validator.c
stub_token_validator_la_LDFLAGS = -module
negotiate_token_validator_la_SOURCES = negotiate_token_validator.c
negotiate_token_validator_la_LDFLAGS = -module $(top_builddir)/lib/gssapi/libgssapi.la

CLEANFILES= 
EXTRA_DIST= NTMakefile
