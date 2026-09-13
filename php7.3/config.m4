dnl +----------------------------------------------------------------------+
dnl | idcsmart - IDCSystem License Bypass Extension                        |
dnl | PHP Version: 7.3 (API20180731,NTS)                                  |
dnl +----------------------------------------------------------------------+

PHP_ARG_WITH([idcsmart],
  [for idcsmart support],
  [AS_HELP_STRING([--with-idcsmart],
    [Include idcsmart support])])

if test "$PHP_IDCSMART" != "no"; then
  AC_DEFINE(HAVE_IDCSMART, 1, [ Have idcsmart support ])

  PHP_NEW_EXTENSION(idcsmart, idcsmart.c, $ext_shared,, -DZEND_ENABLE_STATIC_TSRMLS_CACHE=1)
fi
