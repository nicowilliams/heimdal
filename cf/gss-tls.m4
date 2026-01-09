dnl
dnl Configure option for GSS-TLS mechanism backend selection
dnl
dnl --with-gss-tls=BACKEND where BACKEND is one of:
dnl   auto     - prefer s2n-tls if available, fall back to openssl (default)
dnl   s2n-tls  - require s2n-tls
dnl   openssl  - use OpenSSL's libssl
dnl   no       - disable GSS-TLS mechanism
dnl

AC_DEFUN([KRB_GSS_TLS], [
AC_ARG_WITH([gss-tls],
    AS_HELP_STRING([--with-gss-tls=BACKEND],
        [GSS-TLS backend: auto, s2n-tls, openssl, or no (default: auto)]),
    [gss_tls_backend=$withval],
    [gss_tls_backend=auto])

gss_tls_s2n=no
gss_tls_openssl=no

case "$gss_tls_backend" in
    auto)
        dnl Prefer s2n-tls if available (better API for this use case)
        if test "$s2n" = "yes"; then
            gss_tls_s2n=yes
            AC_MSG_NOTICE([GSS-TLS: using s2n-tls backend])
        elif test "$openssl" = "yes"; then
            gss_tls_openssl=yes
            AC_MSG_NOTICE([GSS-TLS: using OpenSSL backend])
        else
            AC_MSG_NOTICE([GSS-TLS: disabled (no TLS library available)])
        fi
        ;;
    s2n-tls|s2n)
        if test "$s2n" != "yes"; then
            AC_MSG_ERROR([s2n-tls requested for GSS-TLS but s2n-tls not found])
        fi
        gss_tls_s2n=yes
        AC_MSG_NOTICE([GSS-TLS: using s2n-tls backend])
        ;;
    openssl)
        if test "$openssl" != "yes"; then
            AC_MSG_ERROR([OpenSSL requested for GSS-TLS but OpenSSL not found])
        fi
        gss_tls_openssl=yes
        AC_MSG_NOTICE([GSS-TLS: using OpenSSL backend])
        ;;
    no|none)
        AC_MSG_NOTICE([GSS-TLS: disabled by request])
        ;;
    *)
        AC_MSG_ERROR([Unknown GSS-TLS backend: $gss_tls_backend (use auto, s2n-tls, openssl, or no)])
        ;;
esac

if test "$gss_tls_s2n" = "yes"; then
    AC_DEFINE([GSS_TLS_S2N], 1, [Define if using s2n-tls for GSS-TLS mechanism])
fi

if test "$gss_tls_openssl" = "yes"; then
    AC_DEFINE([GSS_TLS_OPENSSL], 1, [Define if using OpenSSL for GSS-TLS mechanism])
    dnl Check for libssl (in addition to libcrypto which is already linked)
    save_LIBS="$LIBS"
    save_LDFLAGS="$LDFLAGS"
    save_CPPFLAGS="$CPPFLAGS"
    LDFLAGS="${LDFLAGS} ${LDFLAGS_openssl}"
    CPPFLAGS="${CPPFLAGS} ${INCLUDE_openssl}"
    AC_CHECK_LIB([ssl], [SSL_CTX_new],
        [LIB_openssl_ssl="-lssl"],
        [AC_MSG_ERROR([libssl not found, required for OpenSSL GSS-TLS backend])],
        [${LIB_openssl_crypto}])
    LIBS="$save_LIBS"
    LDFLAGS="$save_LDFLAGS"
    CPPFLAGS="$save_CPPFLAGS"
    AC_SUBST([LIB_openssl_ssl])
fi

AM_CONDITIONAL([GSS_TLS_S2N], [test "$gss_tls_s2n" = "yes"])
AM_CONDITIONAL([GSS_TLS_OPENSSL], [test "$gss_tls_openssl" = "yes"])
AM_CONDITIONAL([GSS_TLS], [test "$gss_tls_s2n" = "yes" -o "$gss_tls_openssl" = "yes"])
])
