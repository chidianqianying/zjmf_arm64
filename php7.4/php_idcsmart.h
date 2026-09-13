#ifndef PHP_IDCSMART_H
#define PHP_IDCSMART_H

extern zend_module_entry idcsmart_module_entry;
#define phpext_idcsmart_ptr &idcsmart_module_entry

#define PHP_IDCSMART_VERSION "0.3.1"

#ifdef PHP_WIN32
#   define PHP_IDCSMART_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#   define PHP_IDCSMART_API __attribute__ ((visibility("default")))
#else
#   define PHP_IDCSMART_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(idcsmart)
    char *auth_url;
    char *license_url;
    char *public_key;
    char *block_url;
    char *module_name;
    char *market_url;
ZEND_END_MODULE_GLOBALS(idcsmart)

ZEND_EXTERN_MODULE_GLOBALS(idcsmart)
#define IDCSMART_G(v) ZEND_MODULE_GLOBALS_ACCESSOR(idcsmart, v)

#endif
