dnl $Id$
dnl
dnl Test for s2n-tls library (used by GSS-TLS mechanism)
dnl

AC_DEFUN([KRB_S2N],[
AC_WITH_ALL([s2n])

AC_MSG_CHECKING([for s2n-tls library])

s2n=no
INCLUDE_s2n=
LIB_s2n=

if test "$with_s2n" = "yes"; then
    with_s2n=/usr
fi

if test "$with_s2n" != "no" -a "$with_s2n" != ""; then
    saved_CFLAGS="${CFLAGS}"
    saved_LDFLAGS="${LDFLAGS}"

    if test "$with_s2n_include" != ""; then
        INCLUDE_s2n="-I${with_s2n_include}"
    elif test "$with_s2n" != "/usr"; then
        INCLUDE_s2n="-I${with_s2n}/include"
    fi

    if test "$with_s2n_lib" != ""; then
        LIB_s2n="-L${with_s2n_lib}"
        s2n_libdir="${with_s2n_lib}"
    elif test "${with_s2n}" != "/usr"; then
        dnl Detect lib vs lib64
        s2n_libdir=""
        if test -f "${with_s2n}/lib64/libs2n.so" -o \
                -f "${with_s2n}/lib64/libs2n.dylib" -o \
                -f "${with_s2n}/lib64/libs2n.a"; then
            s2n_libdir="${with_s2n}/lib64"
        elif test -f "${with_s2n}/lib/libs2n.so" -o \
                  -f "${with_s2n}/lib/libs2n.dylib" -o \
                  -f "${with_s2n}/lib/libs2n.a"; then
            s2n_libdir="${with_s2n}/lib"
        elif test -d "${with_s2n}/lib64"; then
            s2n_libdir="${with_s2n}/lib64"
        elif test -d "${with_s2n}/lib"; then
            s2n_libdir="${with_s2n}/lib"
        fi
        if test -n "$s2n_libdir"; then
            LIB_s2n="-L${s2n_libdir}"
        fi
    fi

    dnl Add rpath for non-system s2n installations
    if test -n "$s2n_libdir" -a "$s2n_libdir" != "/usr/lib" -a "$s2n_libdir" != "/usr/lib64"; then
        case "$host_os" in
        darwin*)
            LIB_s2n="${LIB_s2n} -Wl,-rpath,${s2n_libdir}"
            ;;
        *)
            LIB_s2n="${LIB_s2n} -Wl,-rpath,${s2n_libdir}"
            ;;
        esac
    fi

    CFLAGS="${INCLUDE_s2n} ${CFLAGS}"
    LDFLAGS="${LIB_s2n} ${LDFLAGS}"

    dnl Check for s2n_init function which is the main initialization entry point
    AC_CHECK_LIB([s2n], [s2n_init],
                 [LIB_s2n="${LIB_s2n} -ls2n"; s2n=yes], [s2n=no],
                 [${LIB_openssl_crypto}])

    if test "$s2n" = "yes"; then
        dnl Check for required header
        AC_CHECK_HEADER([s2n.h], [], [s2n=no])
    fi

    if test "$s2n" = "yes"; then
        AC_DEFINE([HAVE_S2N], 1, [Define if you have s2n-tls library])
        AC_MSG_RESULT([yes])
    else
        INCLUDE_s2n=
        LIB_s2n=
        AC_MSG_RESULT([no])
    fi

    CFLAGS="${saved_CFLAGS}"
    LDFLAGS="${saved_LDFLAGS}"
else
    AC_MSG_RESULT([disabled])
fi

AC_SUBST(INCLUDE_s2n)
AC_SUBST(LIB_s2n)
AM_CONDITIONAL([HAVE_S2N], [test "$s2n" = "yes"])
])
