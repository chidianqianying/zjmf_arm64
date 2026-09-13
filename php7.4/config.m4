PHP_ARG_ENABLE(idcsmart, whether to enable idcsmart support,
[  --enable-idcsmart       Enable idcsmart support])

if test "$PHP_IDCSMART" != "no"; then
  PHP_NEW_EXTENSION(idcsmart, idcsmart.c, $ext_shared)
fi
