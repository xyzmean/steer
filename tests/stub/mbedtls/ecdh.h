/* См. tests/stub/mbedtls/md.h — заглушка для ext-syntax. Из ecdh наши исходники
 * не зовут ничего: X25519 собран руками поверх ecp, заголовок тянется по
 * привычке. Пустой файл честнее выдуманных прототипов. */
#ifndef STEER_TESTSTUB_MBEDTLS_ECDH_H
#define STEER_TESTSTUB_MBEDTLS_ECDH_H
#include "mbedtls/ecp.h"
#endif
