#include <mbedtls/bignum.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <nabto/nabto_device.h>
#include <nabto/nabto_device_experimental.h>
#include <platform/np_logging.h>
#include <platform/np_logging_defines.h>
#include <platform/np_timestamp_wrapper.h>

#include "nabto_device_defines.h"
#include "nabto_device_threads.h"

#define LOG NABTO_LOG_MODULE_PLATFORM

static void sha256_speed_test(struct nabto_device_context* dev);
static void p256r1_multiplication_speed_test(struct nabto_device_context* dev);
static void curve25519_multiplication_speed_test(
    struct nabto_device_context* dev);

NabtoDeviceError NABTO_DEVICE_API
nabto_device_crypto_speed_test(NabtoDevice* device)
{
    struct nabto_device_context* dev = (struct nabto_device_context*)device;
    nabto_device_threads_mutex_lock(dev->eventMutex);

    sha256_speed_test(dev);
    p256r1_multiplication_speed_test(dev);
    curve25519_multiplication_speed_test(dev);

    nabto_device_threads_mutex_unlock(dev->eventMutex);
    return NABTO_DEVICE_EC_OK;
}

void sha256_speed_test(struct nabto_device_context* dev)
{
    NABTO_LOG_INFO(LOG, "Testing SHA256 performance");
    uint8_t data[1024];
    uint8_t output[32];

    size_t iterations = 1000;

    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);

    for (size_t i = 0; i < iterations; i++) {
        mbedtls_sha256(data, sizeof(data), output, 0);
    }

    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "SHA256 took %d ms for %d rounds of size %d each",
                   elapsed, iterations, sizeof(data));
}

void p256r1_multiplication_speed_test(struct nabto_device_context* dev)
{
    NABTO_LOG_INFO(LOG, "Testing p256r1 multiplication performance");

    // do multiplication

    int status;
    // calculcate Q = d*G where d is a bignumber and G is the generator for the
    // group P256r1

    mbedtls_mpi d;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;

    mbedtls_mpi_init(&d);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL, 0)) != 0) {
        NABTO_LOG_ERROR(LOG, " failed mbedtls_ctr_drbg_seed returned %d",
                        ret);
        return;
    }

    status = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "cannot load the group P256R1")
        return;
    }

    // Q = dG
    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);
    ret = mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
    if (ret != 0) {
        NABTO_LOG_ERROR(LOG, " failed mbedtls_ecdh_gen_public returned %d", ret);
        return;
    }
    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);


    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "p256r1 multiplication took %d ms", elapsed);
}

void curve25519_multiplication_speed_test(struct nabto_device_context* dev)
{
    NABTO_LOG_INFO(LOG, "Testing curve 25519 multiplication performance");

    // do multiplication

    int status;
    // calculcate Q = d*G where d is a bignumber and G is the generator for the
    // group curve 25519

    mbedtls_mpi d;
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;

    mbedtls_mpi_init(&d);
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    int ret;
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     NULL, 0)) != 0) {
        NABTO_LOG_ERROR(LOG, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n",
                        ret);
        return;
    }

    status = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_CURVE25519);
    if (status != 0) {
        NABTO_LOG_ERROR(LOG, "cannot load the group cruve25519")
        return;
    }

    uint32_t start = np_timestamp_now_ms(&dev->pl.timestamp);

    ret = mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random,
                                  &ctr_drbg);
    if (ret != 0) {
        NABTO_LOG_ERROR(
            LOG, " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret);
        return;
    }

    uint32_t end = np_timestamp_now_ms(&dev->pl.timestamp);

    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    mbedtls_mpi_free(&d);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    int32_t elapsed = np_timestamp_difference(end, start);
    NABTO_LOG_INFO(LOG, "curve 25519 multiplication took %d ms", elapsed);
}
