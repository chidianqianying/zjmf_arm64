/* +----------------------------------------------------------------------+
 * | idcsmart - IDCSystem License Bypass Extension                        |
 * | Reverse engineered from x86-64 binary for ARM64 recompilation        |
 * | FIXED: curl_setopt redirect & extension_loaded hiding                |
 * +----------------------------------------------------------------------+
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/php_string.h"
#include "php_idcsmart.h"

/* ====================================================================== */
/*  硬编码常量（从 .rodata 段提取）                                         */
/* ====================================================================== */

#define REF_PUBLIC_KEY_LEN      128
#define BLOCK_SOCKET_LEN        37

/* 参考公钥指纹（0x2cf9 处硬编码，128字节）——仅用于匹配 */
static const char ref_public_key[REF_PUBLIC_KEY_LEN + 1] =
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDg6DKmQVwkQCzKcFYb0BBW7N2f"
    "I7DqL4MaiT6vibgEzH3EUFuBCRg3cXqCplJlk13PPbKMWMYsrc5cz7+k08kgTpD4";

/* 阻止的 socket 地址（0x2d80 处硬编码，37字节）——直接阻止，无需配置 */
static const char block_socket_addr[BLOCK_SOCKET_LEN + 1] =
    "ssl://license.soft13.idcsmart.com:443";

/* ====================================================================== */
/*  原始函数指针                                                           */
/* ====================================================================== */

static zif_handler ori_json_decode              = NULL;
static zif_handler ori_openssl_pkey_get_public  = NULL;
static zif_handler ori_curl_setopt              = NULL;
static zif_handler ori_curl_setopt_array        = NULL;
static zif_handler ori_curl_getinfo            = NULL;
static zif_handler ori_file_get_contents        = NULL;
static zif_handler ori_stream_socket_client      = NULL;
static zif_handler ori_extension_loaded           = NULL;
static zif_handler ori_get_loaded_extensions     = NULL;

/* ====================================================================== */
/*  模块全局变量                                                           */
/* ====================================================================== */

ZEND_DECLARE_MODULE_GLOBALS(idcsmart)

/* ====================================================================== */
/*  模块全局变量初始化构造函数                                               */
/* ====================================================================== */

static void php_idcsmart_init_globals(zend_idcsmart_globals *idcsmart_globals)
{
    memset(idcsmart_globals, 0, sizeof(zend_idcsmart_globals));
}

/* ====================================================================== */
/*  INI 配置定义（与 V1 完全一致）                                         */
/* ====================================================================== */

PHP_INI_BEGIN()
    STD_PHP_INI_ENTRY("idcsmart.auth_url",     "",                      PHP_INI_ALL, OnUpdateString, auth_url,     zend_idcsmart_globals, idcsmart_globals)
    STD_PHP_INI_ENTRY("idcsmart.license_url",  "http://154.7.178.154/", PHP_INI_ALL, OnUpdateString, license_url,  zend_idcsmart_globals, idcsmart_globals)
    STD_PHP_INI_ENTRY("idcsmart.public_key",   "",                      PHP_INI_ALL, OnUpdateString, public_key,   zend_idcsmart_globals, idcsmart_globals)
    STD_PHP_INI_ENTRY("idcsmart.block_url",    "",                      PHP_INI_ALL, OnUpdateString, block_url,    zend_idcsmart_globals, idcsmart_globals)
    /* 伪装名：idcsmxart（不是 idcsmart） */
    STD_PHP_INI_ENTRY("idcsmart.module_name",  "idcsmxart",             PHP_INI_ALL, OnUpdateString, module_name,  zend_idcsmart_globals, idcsmart_globals)
    STD_PHP_INI_ENTRY("idcsmart.market_url",   "",                      PHP_INI_ALL, OnUpdateString, market_url,   zend_idcsmart_globals, idcsmart_globals)
PHP_INI_END()

/* ====================================================================== */
/*  辅助函数                                                               */
/* ====================================================================== */

static char* replace_url_prefix(const char *url, size_t url_len,
                                 const char *old_prefix,
                                 const char *new_prefix,
                                 size_t *new_len)
{
    size_t old_len = strlen(old_prefix);

    if (old_len > 0 && url_len >= old_len && strncmp(url, old_prefix, old_len) == 0) {
        size_t new_prefix_len = strlen(new_prefix);
        *new_len = new_prefix_len + (url_len - old_len);
        char *new_url = emalloc(*new_len + 1);
        memcpy(new_url, new_prefix, new_prefix_len);
        memcpy(new_url + new_prefix_len, url + old_len, url_len - old_len);
        new_url[*new_len] = '\0';
        return new_url;
    }
    return NULL;
}

static void php_override_func(const char *name, size_t name_len,
                               zif_handler new_handler,
                               zif_handler *orig_handler)
{
    zend_function *func = zend_hash_str_find_ptr(CG(function_table), name, name_len);
    if (func && orig_handler) {
        *orig_handler = func->internal_function.handler;
        func->internal_function.handler = new_handler;
    }
}

/* 实时读取 INI，解决 ZTS 下 ini_set 不生效问题 */
static char* get_ini_str(const char *name)
{
    return zend_ini_string((char*)name, strlen(name), 0);
}

/* ====================================================================== */
/*  1. json_decode - 直接调用原始函数，避免递归                            */
/* ====================================================================== */
PHP_FUNCTION(my_json_decode)
{
    /* 直接调用原始 json_decode，不解析参数 */
    ori_json_decode(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    /* 检查返回值 */
    if (Z_TYPE_P(return_value) != IS_ARRAY) {
        return;
    }

    /* V1 行为：仅当配置了 auth_url（长度>1）时才处理 */
    char *auth_url = get_ini_str("idcsmart.auth_url");
    if (!auth_url || strlen(auth_url) <= 1) {
        return;
    }

    /* 检查授权相关 key */
    if (!zend_hash_str_exists(Z_ARRVAL_P(return_value), "license_info", 12) &&
        !zend_hash_str_exists(Z_ARRVAL_P(return_value), "license_status", 14) &&
        !zend_hash_str_exists(Z_ARRVAL_P(return_value), "key", 3)) {
        return;
    }

    /* 分割 auth_url */
    zval delim, urls;
    ZVAL_STRINGL(&delim, ",", 1);

    zend_string *auth_zstr = zend_string_init(auth_url, strlen(auth_url), 0);
    php_explode(Z_STR(delim), auth_zstr, &urls, LONG_MAX);
    zend_string_release(auth_zstr);
    zval_ptr_dtor(&delim);

    if (zend_hash_num_elements(Z_ARRVAL(urls)) == 0) {
        zval_ptr_dtor(&urls);
        return;
    }

    /* 将 URL 添加到结果数组 */
    zval *val;
    ZEND_HASH_FOREACH_VAL(Z_ARRVAL(urls), val) {
        if (Z_TYPE_P(val) == IS_STRING && Z_STRLEN_P(val) > 0) {
            add_next_index_string(return_value, Z_STRVAL_P(val));
        }
    } ZEND_HASH_FOREACH_END();

    zval_ptr_dtor(&urls);
}

/* ====================================================================== */
/*  2. openssl_pkey_get_public                                            */
/* ====================================================================== */
PHP_FUNCTION(my_openssl_pkey_get_public)
{
    zend_string *cert;
    char *pub_pos;

    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STR(cert)
    ZEND_PARSE_PARAMETERS_END();

    /* 长度检查：0x7f < len <= 0x3ff */
    if (ZSTR_LEN(cert) <= 0x7f || ZSTR_LEN(cert) > 0x3ff) {
        ori_openssl_pkey_get_public(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    /* 搜索 'M' 字符 */
    pub_pos = memchr(ZSTR_VAL(cert), 'M', ZSTR_LEN(cert));
    if (!pub_pos) {
        ori_openssl_pkey_get_public(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    /* 检查偏移 0x7f 处是否为 '4' */
    if (pub_pos[0x7f] != '4') {
        ori_openssl_pkey_get_public(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    /* 比较 0x7e 字节内容（公钥指纹匹配，参考值 0x2cf9） */
    if (memcmp(pub_pos + 1, ref_public_key, 0x7e) != 0) {
        ori_openssl_pkey_get_public(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    /* V1 行为：仅当配置了 public_key（长度>1）时才替换 */
    char *new_key = get_ini_str("idcsmart.public_key");
    if (!new_key || strlen(new_key) <= 1) {
        ori_openssl_pkey_get_public(INTERNAL_FUNCTION_PARAM_PASSTHRU);
        return;
    }

    RETURN_STR(zend_string_init(new_key, strlen(new_key), 0));
}

/* ====================================================================== */
/*  3. curl_setopt - FIX: 直接修改 execute_data 参数                         */
/* ====================================================================== */
PHP_FUNCTION(my_curl_setopt)
{
    /* FIX: _zend_get_parameters_array_ex 获取的是参数副本
     * 必须直接修改 execute_data 中的 zval 才能生效 */
    int argc = ZEND_NUM_ARGS();
    zend_long option;
    zval *value;
    char *url, *new_url;
    char *auth_url, *market_url, *license_url;
    size_t url_len, new_len;

    if (argc != 3) {
        WRONG_PARAM_COUNT;
    }

    /* 直接通过 execute_data 获取参数（与原始so一致） */
    zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
    zval *arg2 = ZEND_CALL_ARG(execute_data, 2);
    zval *arg3 = ZEND_CALL_ARG(execute_data, 3);

    /* 参数类型检查 */
    if (Z_TYPE_P(arg1) != IS_RESOURCE) {
        zend_wrong_parameter_type_error(1, IS_RESOURCE, arg1);
        return;
    }
    if (Z_TYPE_P(arg2) != IS_LONG) {
        zend_wrong_parameter_type_error(2, IS_LONG, arg2);
        return;
    }

    option = Z_LVAL_P(arg2);
    value = arg3;

    /* 拦截 CURLOPT_URL (10002) */
    if (option == 10002 && Z_TYPE_P(value) == IS_STRING) {
        url = Z_STRVAL_P(value);
        url_len = Z_STRLEN_P(value);

        /* V1 行为：使用 INI 配置值（实时读取） */
        auth_url = get_ini_str("idcsmart.auth_url");
        market_url = get_ini_str("idcsmart.market_url");
        license_url = get_ini_str("idcsmart.license_url");

        /* license_url 必须有值（INI 默认已设置） */
        if (!license_url || strlen(license_url) <= 1) {
            ori_curl_setopt(INTERNAL_FUNCTION_PARAM_PASSTHRU);
            return;
        }

        new_url = NULL;

        /* 尝试匹配 auth_url（必须配置了才匹配） */
        if (auth_url && strlen(auth_url) > 1) {
            new_url = replace_url_prefix(url, url_len, auth_url, license_url, &new_len);
        }

        /* 尝试匹配 market_url（必须配置了才匹配） */
        if (!new_url && market_url && strlen(market_url) > 1) {
            new_url = replace_url_prefix(url, url_len, market_url, license_url, &new_len);
        }

        /* FIX: 如果没有匹配到 auth_url/market_url，但 URL 包含 license.soft13.idcsmart.com
         * 也进行重定向（匹配原so行为） */
        if (!new_url) {
            const char *license_host = "https://license.soft13.idcsmart.com/";
            size_t host_len = strlen(license_host);
            if (url_len >= host_len && strncmp(url, license_host, host_len) == 0) {
                new_url = replace_url_prefix(url, url_len, license_host, license_url, &new_len);
            }
        }

        if (new_url) {
            /* FIX: 匹配原so行为，手动构造 zend_string 并直接写入 execute_data
             * 原so使用 type_info = 0x106 (IS_STRING_EX)，表示引用计数字符串 */
            zval_ptr_dtor(value);
            
            zend_string *new_zstr = zend_string_init(new_url, new_len, 0);
            Z_STR_P(value) = new_zstr;
            Z_TYPE_INFO_P(value) = IS_STRING_EX;
            
            efree(new_url);
        }
    }

    ori_curl_setopt(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ====================================================================== */
/*  4. curl_setopt_array - FIX: 直接修改 execute_data 参数                    */
/* ====================================================================== */
PHP_FUNCTION(my_curl_setopt_array)
{
    /* FIX: 直接操作 execute_data 中的参数，与 curl_setopt 保持一致 */
    int argc = ZEND_NUM_ARGS();
    zval *arr, *url_val;
    char *url, *new_url;
    char *auth_url, *market_url, *license_url;
    size_t url_len, new_len;

    if (argc != 2) {
        WRONG_PARAM_COUNT;
    }

    /* 直接通过 execute_data 获取参数 */
    zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
    zval *arg2 = ZEND_CALL_ARG(execute_data, 2);

    if (Z_TYPE_P(arg1) != IS_RESOURCE) {
        zend_wrong_parameter_type_error(1, IS_RESOURCE, arg1);
        return;
    }
    if (Z_TYPE_P(arg2) != IS_ARRAY) {
        zend_wrong_parameter_type_error(2, IS_ARRAY, arg2);
        return;
    }

    arr = arg2;

    /* 查找 CURLOPT_URL (10002) */
    url_val = zend_hash_index_find(Z_ARRVAL_P(arr), 10002);
    if (url_val && Z_TYPE_P(url_val) == IS_STRING) {
        url = Z_STRVAL_P(url_val);
        url_len = Z_STRLEN_P(url_val);

        /* V1 行为：使用 INI 配置值（实时读取） */
        auth_url = get_ini_str("idcsmart.auth_url");
        market_url = get_ini_str("idcsmart.market_url");
        license_url = get_ini_str("idcsmart.license_url");

        if (!license_url || strlen(license_url) <= 1) {
            ori_curl_setopt_array(INTERNAL_FUNCTION_PARAM_PASSTHRU);
            return;
        }

        new_url = NULL;

        if (auth_url && strlen(auth_url) > 1) {
            new_url = replace_url_prefix(url, url_len, auth_url, license_url, &new_len);
        }
        if (!new_url && market_url && strlen(market_url) > 1) {
            new_url = replace_url_prefix(url, url_len, market_url, license_url, &new_len);
        }

        /* FIX: 同样处理硬编码的 license host */
        if (!new_url) {
            const char *license_host = "https://license.soft13.idcsmart.com/";
            size_t host_len = strlen(license_host);
            if (url_len >= host_len && strncmp(url, license_host, host_len) == 0) {
                new_url = replace_url_prefix(url, url_len, license_host, license_url, &new_len);
            }
        }

        if (new_url) {
            /* FIX: 匹配原so行为 */
            zval_ptr_dtor(url_val);
            
            zend_string *new_zstr = zend_string_init(new_url, new_len, 0);
            Z_STR_P(url_val) = new_zstr;
            Z_TYPE_INFO_P(url_val) = IS_STRING_EX;
            
            efree(new_url);
        }
    }

    ori_curl_setopt_array(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ====================================================================== */
/*  5. curl_getinfo - FIX: 直接读取 execute_data 参数                       */
/* ====================================================================== */
PHP_FUNCTION(my_curl_getinfo)
{
    /* FIX: curl_getinfo 只需要读取参数，不需要修改，两种方法都可以
     * 但为了统一风格，也使用 ZEND_CALL_ARG */
    int argc = ZEND_NUM_ARGS();
    zval *url_val;
    zend_long option = 0;
    char *url, *new_url;
    char *auth_url, *license_url;
    size_t url_len, new_len;

    if (argc < 1 || argc > 2) {
        WRONG_PARAM_COUNT;
    }

    /* 直接通过 execute_data 获取参数 */
    zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
    zval *arg2 = ZEND_CALL_ARG(execute_data, 2);

    if (Z_TYPE_P(arg1) != IS_RESOURCE) {
        zend_wrong_parameter_type_error(1, IS_RESOURCE, arg1);
        return;
    }

    if (argc > 1 && Z_TYPE_P(arg2) != IS_LONG) {
        zend_wrong_parameter_type_error(2, IS_LONG, arg2);
        return;
    }

    if (argc > 1) {
        option = Z_LVAL_P(arg2);
    }

    /* 调用原始函数 */
    ori_curl_getinfo(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    /* 只有1个参数时返回数组，需要处理 */
    if (argc > 1) {
        return;
    }

    if (Z_TYPE_P(return_value) != IS_ARRAY) {
        return;
    }

    /* 查找 "url" key */
    url_val = zend_hash_str_find(Z_ARRVAL_P(return_value), "url", 3);
    if (!url_val || Z_TYPE_P(url_val) != IS_STRING) {
        return;
    }

    url = Z_STRVAL_P(url_val);
    url_len = Z_STRLEN_P(url_val);

    /* V1 行为：使用 INI 配置值，必须两者都配置了才伪装 */
    license_url = get_ini_str("idcsmart.license_url");
    auth_url = get_ini_str("idcsmart.auth_url");

    if (!license_url || strlen(license_url) <= 1 ||
        !auth_url || strlen(auth_url) <= 1) {
        return;
    }

    /* 将 license_url 伪装回 auth_url */
    new_url = replace_url_prefix(url, url_len, license_url, auth_url, &new_len);
    if (new_url) {
        /* FIX: 匹配原so行为 */
        zval_ptr_dtor(url_val);
        
        zend_string *new_zstr = zend_string_init(new_url, new_len, 0);
        Z_STR_P(url_val) = new_zstr;
        Z_TYPE_INFO_P(url_val) = IS_STRING_EX;
        
        efree(new_url);
    }
}

/* ====================================================================== */
/*  6. file_get_contents - FIX: 直接读取 execute_data 参数                  */
/* ====================================================================== */
PHP_FUNCTION(my_file_get_contents)
{
    /* FIX: file_get_contents 只需要读取参数，使用 ZEND_CALL_ARG 即可 */
    int argc = ZEND_NUM_ARGS();
    zend_string *filename;
    char *block_url;

    if (argc < 1 || argc > 5) {
        WRONG_PARAM_COUNT;
    }

    /* 直接通过 execute_data 获取参数 */
    zval *arg1 = ZEND_CALL_ARG(execute_data, 1);

    if (Z_TYPE_P(arg1) != IS_STRING) {
        zend_wrong_parameter_type_error(1, IS_STRING, arg1);
        return;
    }

    filename = Z_STR_P(arg1);

    /* 检查 block_url（必须配置了才阻止） */
    block_url = get_ini_str("idcsmart.block_url");
    if (block_url && strlen(block_url) > 1) {
        if (ZSTR_LEN(filename) >= strlen(block_url) &&
            strncmp(ZSTR_VAL(filename), block_url, strlen(block_url)) == 0) {
            RETURN_EMPTY_STRING();
        }
    }

    ori_file_get_contents(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ====================================================================== */
/*  7. stream_socket_client - FIX: 直接读取 execute_data 参数               */
/* ====================================================================== */
PHP_FUNCTION(my_stream_socket_client)
{
    /* FIX: stream_socket_client 只需要读取参数，使用 ZEND_CALL_ARG 即可 */
    int argc = ZEND_NUM_ARGS();
    zend_string *remote_socket;

    if (argc < 1) {
        WRONG_PARAM_COUNT;
    }

    /* 直接通过 execute_data 获取参数 */
    zval *arg1 = ZEND_CALL_ARG(execute_data, 1);

    /* 检查第一个参数 */
    if (Z_TYPE_P(arg1) == IS_STRING) {
        remote_socket = Z_STR_P(arg1);

        /* 检查长度 0x25=37 和内容（硬编码阻止） */
        if (ZSTR_LEN(remote_socket) == BLOCK_SOCKET_LEN) {
            if (memcmp(ZSTR_VAL(remote_socket), block_socket_addr, BLOCK_SOCKET_LEN) == 0) {
                RETURN_FALSE;
            }
        }
    }

    ori_stream_socket_client(INTERNAL_FUNCTION_PARAM_PASSTHRU);
}

/* ====================================================================== */
/*  8. extension_loaded - FIX: 同时拦截 "idcsmart" 和 module_name           */
/* ====================================================================== */
PHP_FUNCTION(my_extension_loaded)
{
    /* FIX: 使用 _zend_get_parameters_array_ex 替代 ZEND_CALL_ARG */
    zval args[1];
    int argc = ZEND_NUM_ARGS();
    zend_string *extension_name;
    char *module_name;

    if (argc != 1) {
        WRONG_PARAM_COUNT;
    }

    if (zend_get_parameters_array_ex(argc, args) != SUCCESS) {
        WRONG_PARAM_COUNT;
    }

    if (Z_TYPE(args[0]) != IS_STRING) {
        zend_wrong_parameter_type_error(1, IS_STRING, &args[0]);
        return;
    }

    extension_name = Z_STR(args[0]);

    /* FIX: 先检查是否是 "idcsmart" 本身，如果是直接返回 false
     * 不需要调用原始函数，避免原始函数返回 true */
    if (ZSTR_LEN(extension_name) >= sizeof("idcsmart") - 1 &&
        strncmp(ZSTR_VAL(extension_name), "idcsmart", sizeof("idcsmart") - 1) == 0) {
        RETURN_FALSE;
    }

    /* 调用原始函数 */
    ori_extension_loaded(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    /* 如果查询的是伪装名（module_name），返回 false */
    module_name = get_ini_str("idcsmart.module_name");
    if (module_name && strlen(module_name) > 1) {
        if (ZSTR_LEN(extension_name) >= strlen(module_name) &&
            strncmp(ZSTR_VAL(extension_name), module_name, strlen(module_name)) == 0) {
            RETURN_FALSE;
        }
    }
}

/* ====================================================================== */
/*  9. get_loaded_extensions - FIX: 直接读取 execute_data 参数              */
/* ====================================================================== */
PHP_FUNCTION(my_get_loaded_extensions)
{
    /* FIX: get_loaded_extensions 只需要读取参数，使用 ZEND_CALL_ARG 即可 */
    int argc = ZEND_NUM_ARGS();
    zval *val;
    HashPosition pos;

    if (argc > 1) {
        WRONG_PARAM_COUNT;
    }

    if (argc == 1) {
        zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
        if (Z_TYPE_P(arg1) != IS_TRUE && Z_TYPE_P(arg1) != IS_FALSE) {
            WRONG_PARAM_COUNT;
        }
    }

    /* 调用原始函数 */
    ori_get_loaded_extensions(INTERNAL_FUNCTION_PARAM_PASSTHRU);

    if (Z_TYPE_P(return_value) != IS_ARRAY) {
        return;
    }

    /* 遍历数组，移除 "idcsmart" */
    zend_hash_internal_pointer_reset_ex(Z_ARRVAL_P(return_value), &pos);
    while ((val = zend_hash_get_current_data_ex(Z_ARRVAL_P(return_value), &pos)) != NULL) {
        if (Z_TYPE_P(val) == IS_STRING) {
            if (Z_STRLEN_P(val) >= sizeof("idcsmart") - 1 &&
                strncmp(Z_STRVAL_P(val), "idcsmart", sizeof("idcsmart") - 1) == 0) {
                zend_ulong num_key;
                zend_string *str_key;
                int key_type = zend_hash_get_current_key_ex(Z_ARRVAL_P(return_value), &str_key, &num_key, &pos);
                if (key_type == HASH_KEY_IS_STRING) {
                    zend_hash_del(Z_ARRVAL_P(return_value), str_key);
                } else {
                    zend_hash_index_del(Z_ARRVAL_P(return_value), num_key);
                }
                break;
            }
        }
        zend_hash_move_forward_ex(Z_ARRVAL_P(return_value), &pos);
    }
}

/* ====================================================================== */
/*  模块生命周期                                                           */
/* ====================================================================== */

PHP_MINIT_FUNCTION(idcsmart)
{
    ZEND_INIT_MODULE_GLOBALS(idcsmart, php_idcsmart_init_globals, NULL);
    REGISTER_INI_ENTRIES();

    /* Hook 9 个函数（按原始顺序） */
    php_override_func(ZEND_STRL("json_decode"),
                      PHP_FN(my_json_decode), &ori_json_decode);
    php_override_func(ZEND_STRL("openssl_pkey_get_public"),
                      PHP_FN(my_openssl_pkey_get_public), &ori_openssl_pkey_get_public);
    php_override_func(ZEND_STRL("curl_setopt"),
                      PHP_FN(my_curl_setopt), &ori_curl_setopt);
    php_override_func(ZEND_STRL("curl_setopt_array"),
                      PHP_FN(my_curl_setopt_array), &ori_curl_setopt_array);
    php_override_func(ZEND_STRL("curl_getinfo"),
                      PHP_FN(my_curl_getinfo), &ori_curl_getinfo);
    php_override_func(ZEND_STRL("get_loaded_extensions"),
                      PHP_FN(my_get_loaded_extensions), &ori_get_loaded_extensions);
    php_override_func(ZEND_STRL("extension_loaded"),
                      PHP_FN(my_extension_loaded), &ori_extension_loaded);
    php_override_func(ZEND_STRL("file_get_contents"),
                      PHP_FN(my_file_get_contents), &ori_file_get_contents);
    php_override_func(ZEND_STRL("stream_socket_client"),
                      PHP_FN(my_stream_socket_client), &ori_stream_socket_client);

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(idcsmart)
{
    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_MINFO_FUNCTION(idcsmart)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "idcsmart support", "enabled");
    php_info_print_table_row(2, "Version", PHP_IDCSMART_VERSION);
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

/* ====================================================================== */
/*  函数入口表                                                              */
/* ====================================================================== */

static const zend_function_entry idcsmart_functions[] = {
    PHP_FE_END
};

zend_module_entry idcsmart_module_entry = {
    STANDARD_MODULE_HEADER,
    "idcsmart",
    idcsmart_functions,
    PHP_MINIT(idcsmart),
    PHP_MSHUTDOWN(idcsmart),
    NULL,
    NULL,
    PHP_MINFO(idcsmart),
    PHP_IDCSMART_VERSION,
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_IDCSMART
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(idcsmart)
#endif
