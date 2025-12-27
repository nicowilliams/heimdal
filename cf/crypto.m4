dnl $Id$
dnl
dnl test for crypto libraries:
dnl - libcrypto (from openssl)
dnl - own-built libhcrypto

m4_define([test_headers], [
		#undef KRB5 /* makes md4.h et al unhappy */
		#ifdef HAVE_SYS_TYPES_H
		#include <sys/types.h>
		#endif
		#include <openssl/evp.h>
		#include <openssl/provider.h>
		#include <openssl/encoder.h>
		#include <openssl/core_names.h>
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
		EC_KEY_new();

		OpenSSL_add_all_algorithms();
		AES_encrypt(0,0,0);
		DES_cbc_encrypt(0, 0, 0, schedule, 0, 0);
		RC4(0, 0, 0, 0);])

AC_DEFUN([KRB_CRYPTO],[
AC_ARG_WITH([hcrypto-default-backend],
            AS_HELP_STRING([--with-hcrypto-default-backend=ossl],
                           [specify the default hcrypto backend]),
            [
                if test "$with_val" != ossl -a "$withval" != ""; then
                    AC_MSG_ERROR([hcrypto has been removed 0])
                fi
            ]
            )
AC_ARG_WITH([hcrypto-fallback],
            AS_HELP_STRING([--without-hcrypto-fallback],
                           [disable fallback on hcrypto for unavailable algorithms]),
            [AC_MSG_ERROR([hcrypto has been removed 2])]
            )
AC_WITH_ALL([openssl])

AC_MSG_CHECKING([for crypto library])

openssl=no

if test "$with_openssl" = "yes"; then
        with_openssl=/usr
fi
if test "$with_openssl" != "no"; then
        saved_CFLAGS="${CFLAGS}"
        saved_LDFLAGS="${LDFLAGS}"
	INCLUDE_openssl_crypto=
	LIB_openssl_crypto=
	if test "$with_openssl_include" != ""; then
		INCLUDE_openssl_crypto="-I${with_openssl_include}"
        else
                INCLUDE_openssl_crypto="-I${with_openssl}/include"
	fi
	if test "$with_openssl_lib" != ""; then
		LIB_openssl_crypto="-L${with_openssl_lib}"
		openssl_libdir="${with_openssl_lib}"
	elif test "${with_openssl}" != "/usr"; then
		dnl Detect lib vs lib64: prefer lib64 on 64-bit Linux if it exists
		dnl and contains libcrypto, otherwise fall back to lib
		openssl_libdir=""
		if test -f "${with_openssl}/lib64/libcrypto.so" -o \
		        -f "${with_openssl}/lib64/libcrypto.dylib"; then
			openssl_libdir="${with_openssl}/lib64"
		elif test -f "${with_openssl}/lib/libcrypto.so" -o \
		          -f "${with_openssl}/lib/libcrypto.dylib"; then
			openssl_libdir="${with_openssl}/lib"
		elif test -d "${with_openssl}/lib64"; then
			openssl_libdir="${with_openssl}/lib64"
		elif test -d "${with_openssl}/lib"; then
			openssl_libdir="${with_openssl}/lib"
		fi
		if test -n "$openssl_libdir"; then
			LIB_openssl_crypto="-L${openssl_libdir}"
		fi
	fi
	dnl Add rpath for non-system OpenSSL installations
	if test -n "$openssl_libdir" -a "$openssl_libdir" != "/usr/lib" -a "$openssl_libdir" != "/usr/lib64"; then
		case "$host_os" in
		darwin*)
			dnl macOS uses -rpath with @loader_path or absolute path
			LIB_openssl_crypto="${LIB_openssl_crypto} -Wl,-rpath,${openssl_libdir}"
			;;
		*)
			dnl Linux and other ELF systems
			LIB_openssl_crypto="${LIB_openssl_crypto} -Wl,-rpath,${openssl_libdir}"
			;;
		esac
	fi
	CFLAGS="${INCLUDE_openssl_crypto} ${CFLAGS}"
        LDFLAGS="${LIB_openssl_crypto} ${LDFLAGS}"
        AC_CHECK_LIB([crypto], [OPENSSL_init],
                     [LIB_openssl_crypto="${LIB_openssl_crypto} -lcrypto"; openssl=yes], [openssl=no], [])
        if test "$openssl" = "yes"; then
            AC_CHECK_LIB([crypto],
                         [OSSL_EC_curve_nid2name],
                         [AC_DEFINE_UNQUOTED([HAVE_OPENSSL_30], 1,
                                             [whether OpenSSL is 3.0 or higher])]
                         )
            AC_CHECK_HEADERS([openssl/fips.h],
                             [AC_DEFINE_UNQUOTED([HAVE_OPENSSL_FIPS_H], 1,
                                                 [whether openssl/fips.h is available])]
                             )
            AC_CHECK_LIB([crypto],
                         [FIPS_mode_set],
                         [AC_DEFINE_UNQUOTED([HAVE_OPENSSL_FIPS_MODE_SET_API], 1,
                                             [whether FIPS_mode_set API is available])]
                         )
        fi
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
        if test "$openssl" = "no"; then
                INCLUDE_openssl_crypto=
                LIB_openssl_crypto=
        fi
        CFLAGS="${saved_CFLAGS}"
        LDFLAGS="${saved_LDFLAGS}"
fi

AC_ARG_WITH(pkcs11-module,
                       AS_HELP_STRING([--with-pkcs11-module=path],
                                      [use PKCS11 module in path]),
                       [pkcs11_module="$withval"],
                       [])

if test "$pkcs11_module" != ""; then
  AC_DEFINE_UNQUOTED(PKCS11_MODULE_PATH, "$pkcs11_module", [path to PKCS11 module])
  openssl=no
fi

dnl Check for OpenSSL PKCS#11 provider (pkcs11-provider project)
dnl It installs into the OpenSSL modules directory
openssl_pkcs11_provider=""
if test "$openssl" = "yes"; then
    if test -n "$openssl_libdir"; then
        pkcs11_provider_path="${openssl_libdir}/ossl-modules/pkcs11.so"
    else
        pkcs11_provider_path="/usr/lib/ossl-modules/pkcs11.so"
    fi
    AC_MSG_CHECKING([for OpenSSL PKCS11 provider])
    if test -f "$pkcs11_provider_path"; then
        openssl_pkcs11_provider="$pkcs11_provider_path"
        AC_MSG_RESULT([$openssl_pkcs11_provider])
    else
        AC_MSG_RESULT([not found at $pkcs11_provider_path])
    fi
fi
AC_SUBST(OPENSSL_PKCS11_PROVIDER, [$openssl_pkcs11_provider])
AM_CONDITIONAL([HAVE_OPENSSL_PKCS11_PROVIDER], [test "x$openssl_pkcs11_provider" != "x"])

if test "$openssl" != "yes"; then
    AC_MSG_ERROR([OpenSSL is required])
fi

AC_SUBST(INCLUDE_openssl_crypto)
AC_SUBST(LIB_openssl_crypto)

dnl
dnl Legacy/weak encryption type options
dnl

dnl Single DES (weak crypto) - disabled by default for security
AC_ARG_WITH([1des],
    AS_HELP_STRING([--with-1des], [enable single DES encryption (weak, for legacy compatibility)]),
    [with_1des=$withval],
    [with_1des=no])
AC_MSG_CHECKING([whether to enable single DES encryption])
if test "$with_1des" = "yes"; then
    AC_DEFINE([HEIM_WEAK_CRYPTO], 1, [Define to enable single DES encryption support])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([HEIM_WEAK_CRYPTO], [test "$with_1des" = "yes"])

dnl Triple DES - enabled by default for legacy compatibility
AC_ARG_WITH([3des],
    AS_HELP_STRING([--with-3des], [enable triple DES encryption (default: yes)]),
    [with_3des=$withval],
    [with_3des=yes])
AC_MSG_CHECKING([whether to enable triple DES encryption])
if test "$with_3des" = "yes"; then
    AC_DEFINE([HEIM_DES3], 1, [Define to enable triple DES encryption support])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([HEIM_DES3], [test "$with_3des" = "yes"])

dnl ARCFOUR/RC4 - enabled by default (still used by some Windows systems)
AC_ARG_WITH([arcfour],
    AS_HELP_STRING([--with-arcfour], [enable ARCFOUR/RC4 encryption (default: yes)]),
    [with_arcfour=$withval],
    [with_arcfour=yes])
AC_MSG_CHECKING([whether to enable ARCFOUR encryption])
if test "$with_arcfour" = "yes"; then
    AC_DEFINE([HEIM_ARCFOUR], 1, [Define to enable ARCFOUR/RC4 encryption support])
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
fi
AM_CONDITIONAL([HEIM_ARCFOUR], [test "$with_arcfour" = "yes"])

])
