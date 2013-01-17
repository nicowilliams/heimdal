dnl
dnl $Id$
dnl
dnl Test for transparent unions.
dnl

AC_DEFUN([AC_HAVE_C_TRANSPARENT_UNION], [
	AC_CACHE_CHECK([if the compiler supports transparent unions],[rk_cv_c_transparent_union],[
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[]],[[union u { char *s; int *i; }; typedef union u U __attribute__ ((__transparent_union__));]])],
		[rk_cv_c_transparent_union=yes],
		[rk_cv_c_transparent_union=no])])
	if test "$rk_cv_c_transparent_union" = yes; then
		AC_DEFINE([HAVE_C_TRANSPARENT_UNION], [1],
			[Define if your compiler supports transparent unions.])
	fi
])
