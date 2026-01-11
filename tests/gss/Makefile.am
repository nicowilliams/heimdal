# $Id$

include $(top_srcdir)/Makefile.am.common

.NOTPARALLEL:

noinst_DATA = krb5.conf krb5-nodns.conf new_clients_k5.conf mech

SCRIPT_TESTS = check-basic check-nodns check-gss check-gssmask check-context check-spnego check-negoex

# When both TLS backends are compiled, test each separately
# When only one backend is available, just run check-tls
if GSS_TLS_BOTH
SCRIPT_TESTS += check-tls-openssl check-tls-s2n
else
if GSS_TLS
SCRIPT_TESTS += check-tls
endif
endif

TESTS = $(SCRIPT_TESTS)

check_SCRIPTS = $(SCRIPT_TESTS)

port = 49188

do_subst = sed \
	-e 's,[@]srcdir[@],$(abs_srcdir),g' \
	-e 's,[@]srcdirabs[@],$(abs_srcdir),g' \
	-e 's,[@]top_srcdir[@],$(abs_top_srcdir),g' \
	-e 's,[@]env_setup[@],$(abs_top_builddir)/tests/bin/setup-env,g' \
	-e 's,[@]port[@],$(port),g' \
	-e 's,[@]objdir[@],$(abs_top_builddir)/tests/gss,g' \
	-e 's,[@]objdirabs[@],$(abs_top_builddir)/tests/gss,g'

check-gss: check-gss.in Makefile
	$(do_subst) < $(srcdir)/check-gss.in > check-gss.tmp && \
	chmod +x check-gss.tmp && \
	mv check-gss.tmp check-gss

check-gssmask: check-gssmask.in Makefile
	$(do_subst) < $(srcdir)/check-gssmask.in > check-gssmask.tmp && \
	chmod +x check-gssmask.tmp && \
	mv check-gssmask.tmp check-gssmask

check-context: check-context.in Makefile
	$(do_subst) < $(srcdir)/check-context.in > check-context.tmp && \
	chmod +x check-context.tmp && \
	mv check-context.tmp check-context

check-spnego: check-spnego.in Makefile
	$(do_subst) < $(srcdir)/check-spnego.in > check-spnego.tmp && \
	chmod +x check-spnego.tmp && \
	mv check-spnego.tmp check-spnego

check-basic: check-basic.in Makefile
	$(do_subst) < $(srcdir)/check-basic.in > check-basic.tmp && \
	chmod +x check-basic.tmp && \
	mv check-basic.tmp check-basic

check-nodns: check-nodns.in Makefile
	$(do_subst) < $(srcdir)/check-nodns.in > check-nodns.tmp && \
	chmod +x check-nodns.tmp && \
	mv check-nodns.tmp check-nodns

check-negoex: check-negoex.in Makefile
	$(do_subst) < $(srcdir)/check-negoex.in > check-negoex.tmp && \
	chmod +x check-negoex.tmp && \
	mv check-negoex.tmp check-negoex

check-tls: check-tls.in Makefile
	$(do_subst) < $(srcdir)/check-tls.in > check-tls.tmp && \
	chmod +x check-tls.tmp && \
	mv check-tls.tmp check-tls

check-tls-openssl: check-tls-openssl.in check-tls Makefile
	$(do_subst) < $(srcdir)/check-tls-openssl.in > check-tls-openssl.tmp && \
	chmod +x check-tls-openssl.tmp && \
	mv check-tls-openssl.tmp check-tls-openssl

check-tls-s2n: check-tls-s2n.in check-tls Makefile
	$(do_subst) < $(srcdir)/check-tls-s2n.in > check-tls-s2n.tmp && \
	chmod +x check-tls-s2n.tmp && \
	mv check-tls-s2n.tmp check-tls-s2n

krb5.conf: krb5.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5.conf.in > krb5.conf.tmp && \
	mv krb5.conf.tmp krb5.conf

krb5-nodns.conf: krb5-nodns.conf.in Makefile
	$(do_subst) < $(srcdir)/krb5-nodns.conf.in > krb5-nodns.conf.tmp && \
	mv krb5-nodns.conf.tmp krb5-nodns.conf

new_clients_k5.conf: new_clients_k5.conf.in Makefile
	$(do_subst) < $(srcdir)/new_clients_k5.conf.in > new_clients_k5.conf.tmp && \
	mv new_clients_k5.conf.tmp new_clients_k5.conf

mech: mech.in Makefile
	$(do_subst) < $(srcdir)/mech.in > mech.tmp && \
	mv mech.tmp mech

CLEANFILES= \
	$(TESTS) \
	foopassword \
	barpassword \
	krb5ccfile \
	krb5ccfile-ds \
	server.keytab \
	krb5.conf \
	krb5-nodns.conf \
	new_clients_k5.conf \
	mech \
	current-db* \
	*.log \
	*.pid \
	*.pem \
	tempfile \
	check-basic.tmp \
	check-nodns.tmp \
	check-gss.tmp \
	check-gssmask.tmp \
	check-spnego.tmp \
	check-context.tmp \
	check-negoex.tmp \
	check-tls.tmp \
	check-tls-openssl.tmp \
	check-tls-s2n.tmp

EXTRA_DIST = \
	NTMakefile \
	check-basic.in \
	check-nodns.in \
	check-gss.in \
	check-gssmask.in \
	check-spnego.in \
	check-context.in \
	check-negoex.in \
	check-tls.in \
	check-tls-openssl.in \
	check-tls-s2n.in \
	krb5.conf.in \
	krb5-nodns.conf.in \
	include-krb5.conf \
	new_clients_k5.conf.in \
	mech.in
