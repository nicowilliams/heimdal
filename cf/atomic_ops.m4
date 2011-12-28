dnl $Id$
dnl
dnl try to look for an installed HP atomic_ops library
dnl
dnl set LIB_atomic_ops to the what we should link with
dnl set DIR_atomic_ops to if the directory should be built
dnl set CPPFLAGS_atomic_ops to stuff to add to CPPFLAGS

dnl AC_ATOMIC_OPS()
AC_DEFUN([AC_ATOMIC_OPS], [

AC_ARG_WITH(atomic_ops,
	AS_HELP_STRING([--with-atomic_ops=dir],[use the atomic_ops library in dir]),
)

save_CPPFLAGS="${CPPFLAGS}"

case $with_atomic_ops in
yes|"")
  dirs="" ;;
*)
  dirs="$with_atomic_ops" ;;
esac

atomic_ops_installed=no

if test -n "$dirs"; then
    for i in $dirs; do

    AC_MSG_CHECKING(for atomic_ops in $i)

    CPPFLAGS="-I$i/include ${CPPFLAGS}"

    LIB_atomic_ops="-L$i -latomic_ops"
    CPPFLAGS_atomic_ops="-I$i/include"

    AC_PREPROC_IFELSE([AC_LANG_SOURCE([[
    #include <atomic_ops.h>
    ]])],[atomic_ops_installed=yes; break])

    done
else
    AC_MSG_CHECKING(for atomic_ops)

    LIB_atomic_ops="-latomic_ops"
    CPPFLAGS_atomic_ops=""

    AC_PREPROC_IFELSE([AC_LANG_SOURCE([[
    #include <atomic_ops.h>
    ]])],[atomic_ops_installed=yes])

fi

AC_MSG_RESULT($atomic_ops_installed)

CPPFLAGS="$save_CPPFLAGS"

if test "$atomic_ops_installed" != "yes"; then
  LIB_atomic_ops=""
  CPPFLAGS_atomic_ops=""
else
  AC_DEFINE(HAVE_ATOMIC_OPS, 1, [Define if you have atomic_ops.])
fi

AC_SUBST(LIB_atomic_ops)dnl
AC_SUBST(CPPFLAGS_atomic_ops)dnl
])
