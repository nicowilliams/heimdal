dnl $Id$
dnl
dnl test for crypto libraries:
dnl - libcrypto (from openssl)
dnl - own-built libhcrypto

m4_define([test_headers], [
		#undef KRB5 /* makes md4.h et al unhappy */
		#ifdef HAVE_HCRYPTO_W_OPENSSL
		#ifdef HAVE_SYS_TYPES_H
		#include <sys/types.h>
		#endif
		#include <openssl/evp.h>
		#include <openssl/bn.h>
		#include <openssl/md4.h>
		#include <openssl/md5.h>
		#include <openssl/sha.h>
		#include <openssl/des.h>
		#include <openssl/rc4.h>
		#include <openssl/aes.h>
		#include <openssl/rsa.h>
		#include <openssl/dsa.h>
		#include <openssl/dh.h>
		#include <openssl/ec.h>
		#include <openssl/engine.h>
		#include <openssl/ui.h>
		#include <openssl/rand.h>
		#include <openssl/hmac.h>
		#include <openssl/pkcs12.h>
		#else
		#include <hcrypto/evp.h>
		#include <hcrypto/md4.h>
		#include <hcrypto/md5.h>
		#include <hcrypto/sha.h>
		#include <hcrypto/des.h>
		#include <hcrypto/rc4.h>
		#include <hcrypto/aes.h>
		#include <hcrypto/engine.h>
		#include <hcrypto/hmac.h>
		#include <hcrypto/pkcs12.h>
		#endif
		])
m4_define([test_body], [
		void *schedule = 0;
		EVP_MD_CTX mdctx;

		EVP_md4();
		EVP_md5();
		EVP_sha1();
		EVP_sha256();

		EVP_MD_CTX_init(&mdctx);
		EVP_DigestInit_ex(&mdctx, EVP_sha1(), (ENGINE *)0);
		EVP_CIPHER_iv_length(((EVP_CIPHER*)0));
		UI_UTIL_read_pw_string(0,0,0,0);
		RAND_status();
		#ifdef HAVE_HCRYPTO_W_OPENSSL
		EC_KEY_new();
		#endif

		OpenSSL_add_all_algorithms();
		AES_encrypt(0,0,0);
		DES_cbc_encrypt(0, 0, 0, schedule, 0, 0);
		RC4(0, 0, 0, 0);])

AC_DEFUN([KRB_CRYPTO],[
AC_WITH_ALL([openssl])

AC_MSG_CHECKING([for crypto library])

openssl=no

if test "$with_openssl" != "no"; then
	INCLUDE_openssl_crypto=
	LIB_openssl_crypto=
	if test "$with_openssl_include" != ""; then
		INCLUDE_openssl_crypto="-I${with_openssl_include}"
        else
                INCLUDE_openssl_crypto="${with_openssl}/include"
	fi
	if test "$with_openssl_lib" != ""; then
		LIB_openssl_crypto="-L${with_openssl_lib}"
	fi
	CFLAGS="-DHAVE_HCRYPTO_W_OPENSSL ${INCLUDE_openssl_crypto} ${CFLAGS}"
        # XXX What about rpath?  Yeah...
        AC_CHECK_LIB([crypto], [OPENSSL_init],
                     [LIB_openssl_crypto="${LIB_openssl_crypto} -lcrypto"; openssl=yes], [openssl=no], [])
        # These cases are just for static linking on older OSes,
        # presumably.
        if test "$openssl" = "no"; then
                AC_CHECK_LIB([crypto], [OPENSSL_init],
                             [LIB_openssl_crypto="${LIB_openssl_crypto} -lcrypto -ldl"; openssl=yes], [openssl=no], [-ldl])
        fi
        if test "$openssl" = "no"; then
                AC_CHECK_LIB([crypto], [OPENSSL_init],
                             [LIB_openssl_crypto="${LIB_openssl_crypto} -lcrypto -ldl -lnsl"; openssl=yes], [openssl=no], [-ldl -lnsl])
        fi
        if test "$openssl" = "no"; then
                AC_CHECK_LIB([crypto], [OPENSSL_init],
                             [LIB_openssl_crypto="${LIB_openssl_crypto} -lcrypto -ldl -lnsl -lsocket"; openssl=yes], [openssl=no], [-ldl -lnsl -lsocket])
        fi
fi

LIB_hcrypto='$(top_builddir)/lib/hcrypto/libhcrypto.la'
LIB_hcrypto_a='$(top_builddir)/lib/hcrypto/.libs/libhcrypto.a'
LIB_hcrypto_so='$(top_builddir)/lib/hcrypto/.libs/libhcrypto.so'
LIB_hcrypto_appl="-lhcrypto"

AC_MSG_RESULT([included libhcrypto])

AC_ARG_WITH(pkcs11-module,
                       AS_HELP_STRING([--with-pkcs11-module=path],
                                      [use PKCS11 module in path]),
                       [pkcs11_module="$withval"],
                       [])

if test "$pkcs11_module" != ""; then
  AC_DEFINE_UNQUOTED(PKCS11_MODULE_PATH, "$pkcs11_module", [path to PKCS11 module])
  openssl=no
fi

if test "$openssl" = "yes"; then
  AC_DEFINE([HAVE_HCRYPTO_W_OPENSSL], 1, [define to use openssl's libcrypto as the default backend for libhcrypto])
fi
AM_CONDITIONAL(HAVE_HCRYPTO_W_OPENSSL, test "$openssl" = yes)dnl

dnl XXX Remove INCLUDE_hcrypto; no longer used
INCLUDE_hcrypto=

AC_SUBST(INCLUDE_openssl_crypto)
AC_SUBST(LIB_openssl_crypto)
AC_SUBST(INCLUDE_hcrypto)
AC_SUBST(LIB_hcrypto)
AC_SUBST(LIB_hcrypto_a)
AC_SUBST(LIB_hcrypto_so)
AC_SUBST(LIB_hcrypto_appl)
])
