/* См. tests/stub/mbedtls/md.h — заглушка для ext-syntax. mpi живёт здесь же:
 * настоящий ecp.h тянет bignum.h, а наши исходники bignum.h сами не включают. */
#ifndef STEER_TESTSTUB_MBEDTLS_ECP_H
#define STEER_TESTSTUB_MBEDTLS_ECP_H
#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_ECP_RANDOM_FAILED (-0x4D00)

typedef struct { unsigned char opaque[24]; } mbedtls_mpi;

void mbedtls_mpi_init(mbedtls_mpi *X);
void mbedtls_mpi_free(mbedtls_mpi *X);
int mbedtls_mpi_lset(mbedtls_mpi *X, int64_t z);
int mbedtls_mpi_read_binary(mbedtls_mpi *X, const unsigned char *buf, size_t buflen);
int mbedtls_mpi_read_binary_le(mbedtls_mpi *X, const unsigned char *buf, size_t buflen);
int mbedtls_mpi_write_binary_le(const mbedtls_mpi *X, unsigned char *buf, size_t buflen);

typedef enum {
    MBEDTLS_ECP_DP_NONE = 0,
    MBEDTLS_ECP_DP_CURVE25519,
} mbedtls_ecp_group_id;

/* В mbedtls 3.x поля структур помечены MBEDTLS_PRIVATE; для проверки синтаксиса
 * макрос просто раскрывается в имя, как в самой библиотеке при доступе изнутри. */
#ifndef MBEDTLS_PRIVATE
#define MBEDTLS_PRIVATE(member) member
#endif

typedef struct { mbedtls_mpi X, Y, Z; } mbedtls_ecp_point;
typedef struct {
    unsigned char opaque[256];
    mbedtls_ecp_point G;
} mbedtls_ecp_group;

void mbedtls_ecp_group_init(mbedtls_ecp_group *grp);
void mbedtls_ecp_group_free(mbedtls_ecp_group *grp);
int mbedtls_ecp_group_load(mbedtls_ecp_group *grp, mbedtls_ecp_group_id id);
void mbedtls_ecp_point_init(mbedtls_ecp_point *pt);
void mbedtls_ecp_point_free(mbedtls_ecp_point *pt);
int mbedtls_ecp_mul(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                    const mbedtls_mpi *m, const mbedtls_ecp_point *P,
                    int (*f_rng)(void *, unsigned char *, size_t), void *p_rng);
#endif
