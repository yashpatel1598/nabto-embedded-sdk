
#include <nabto/nabto_device.h>

#include <gopt/gopt.h>

#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/rsa.h"
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/x509_csr.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#define MAX_KEY_PEM_SIZE 1024
#define MAX_CRT_PEM_SIZE 1024

struct config {
    const char* productId;
    const char* deviceId;
    const char* keyFile;
    const char* hostname;
    char keyPemBuffer[MAX_KEY_PEM_SIZE];
    char crtPemBuffer[MAX_CRT_PEM_SIZE];
    uint8_t deviceFingerprint[16];
};

static struct config config;

struct streamContext {
    NabtoDeviceStream* stream;
    uint8_t buffer[1500];
    size_t readen;
};

#ifdef _WIN32
#define NEWLINE "\r\n"
#else
#define NEWLINE "\n"
#endif

void print_help(const char* message)
{
    if (message) {
        printf(message);
        printf(NEWLINE);
    }
    printf("test_device" NEWLINE);
    printf(" USAGE test_device -p <productId> -d <deviceId> -k <keyfile>" NEWLINE);
}

bool parse_args(int argc, const char** argv)
{
    const char* productId;
    const char* deviceId;
    const char* keyFile;
    const char* hostname;

    const char* helpLong[] = { "help", 0 };
    const char* productLong[] = { "product", 0 };
    const char* deviceLong[] = { "device", 0 };
    const char* keyFileLong[] = { "keyfile", 0 };
    const char* hostnameLong[] = { "hostname", 0 };

    const struct { int key; int format; const char* shortName; const char*const* longNames; } opts[] = {
        { 1, GOPT_NOARG, "h", helpLong },
        { 2, GOPT_ARG, "p", productLong },
        { 3, GOPT_ARG, "d", deviceLong },
        { 4, GOPT_ARG, "k", keyFileLong },
        { 5, GOPT_ARG, "", hostnameLong },
        {0,0,0,0}
    };

    void *options = gopt_sort( & argc, argv, opts);
    if( gopt( options, 1)) {
        print_help(NULL);
        return false;
    }

    if (gopt_arg(options, 2, &productId)) {
        config.productId = productId;
    } else {
        print_help("Missing product id");
        return false;
    }

    if (gopt_arg(options, 3, &deviceId)) {
        config.deviceId = deviceId;
    } else {
        print_help("Missing device id");
        return false;
    }

    if (gopt_arg(options, 4, &keyFile)) {
        config.keyFile = keyFile;
    } else {
        print_help("Missing key filename");
        return false;
    }

    if (gopt_arg(options, 5, &hostname)) {
        config.hostname = hostname;
    } else {
        print_help("Missing hostname");
        return false;
    }

    return true;
}

bool create_pem_cert(const char* keyPemBuffer)
{
    // 1. load key from pem
    // 2. create crt
    // 3. write crt to pem string.
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_sha256_context sha256;

    int ret;

    mbedtls_pk_init(&key);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_mpi_init(&serial);
    mbedtls_sha256_init(&sha256);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) {
        return false;
    }

    ret = mbedtls_pk_parse_key( &key, (const unsigned char*)config.keyPemBuffer, strlen(config.keyPemBuffer)+1, NULL, 0 );
    if (ret != 0) {
        return false;
    }

    // initialize crt
    mbedtls_x509write_crt_set_subject_key( &crt, &key );
    mbedtls_x509write_crt_set_issuer_key( &crt, &key );

    ret = mbedtls_mpi_read_string( &serial, 10, "1");
    if (ret != 0) {
        return false;
    }

    mbedtls_x509write_crt_set_serial( &crt, &serial );

    ret = mbedtls_x509write_crt_set_subject_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return false;
    }

    ret = mbedtls_x509write_crt_set_issuer_name( &crt, "CN=nabto" );
    if (ret != 0) {
        return false;
    }

    mbedtls_x509write_crt_set_version( &crt, 2 );
    mbedtls_x509write_crt_set_md_alg( &crt, MBEDTLS_MD_SHA256 );

    ret = mbedtls_x509write_crt_set_validity( &crt, "20010101000000", "20491231235959" );
    if (ret != 0) {
        return false;
    }

    ret = mbedtls_x509write_crt_set_basic_constraints( &crt, 1, -1);
    if (ret != 0) {
        return false;
    }

    {
        // write crt
        ret = mbedtls_x509write_crt_pem( &crt, (unsigned char*)config.crtPemBuffer, MAX_CRT_PEM_SIZE,
                                         mbedtls_ctr_drbg_random, &ctr_drbg );

        if (ret != 0) {
            return false;
        }
    }
    {
        // get fingerprint
        uint8_t buffer[256];
        uint8_t hash[32];
        // !!! The key is written to the end of the buffer
        int len = mbedtls_pk_write_pubkey_der( &key, buffer, sizeof(buffer));
        if (len <= 0) {
            return false;
        }

        ret = mbedtls_sha256_ret(buffer+256 - len,  len, hash, false);
        if (ret != 0) {
            return false;
        }
        memcpy(config.deviceFingerprint, hash, 16);
    }

    // TODO cleanup in case of error
	mbedtls_sha256_free(&sha256);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_mpi_free(&serial);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_pk_free(&key);
    return true;
}


bool file_exists(const char* filename)
{
    return (access(filename, R_OK) == 0);
}

bool load_key_from_file(const char* filename)
{
    FILE* f;
    f = fopen(filename, "r");
    if (f == NULL) {
        return false;
    }

    // if the read failed the key is invalid and we will fail later.
    fread(config.keyPemBuffer, 1, MAX_KEY_PEM_SIZE, f);

    fclose(f);
    return true;
}

void handle_coap_get_request(NabtoDeviceCoapRequest* request, void* data)
{
    printf("Received CoAP GET request" NEWLINE);
    const char* responseData = "helloWorld";
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_response_set_code(response, 205);
    nabto_device_coap_response_set_content_format(response, NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8);
    nabto_device_coap_response_set_payload(response, responseData, strlen(responseData));
    nabto_device_coap_response_ready(response);
}

void handle_coap_post_request(NabtoDeviceCoapRequest* request, void* data)
{
    const char* responseData = "helloWorld";
    uint16_t contentFormat;
    NabtoDeviceCoapResponse* response = nabto_device_coap_create_response(request);
    nabto_device_coap_request_get_content_format(request, &contentFormat);
    if (contentFormat != NABTO_DEVICE_COAP_CONTENT_FORMAT_TEXT_PLAIN_UTF8) {
        const char* responseData = "Invalid content format";
        printf("Received CoAP POST request with invalid content format" NEWLINE);
        nabto_device_coap_response_set_code(response, 400);
        nabto_device_coap_response_set_payload(response, responseData, strlen(responseData));
        nabto_device_coap_response_ready(response);
    } else {
        char* payload = (char*)malloc(1500);
        size_t payloadLength;
        nabto_device_coap_request_get_payload(request, (void**)&payload, &payloadLength);
        printf("Received CoAP POST request with a %li byte payload: " NEWLINE "%s", payloadLength, payload);
        nabto_device_coap_response_set_code(response, 205);
        nabto_device_coap_response_set_payload(response, responseData, strlen(responseData));
        nabto_device_coap_response_ready(response);
    }
}

void close_stream(struct streamContext* streamContext)
{
    NabtoDeviceFuture* fut = nabto_device_stream_close(streamContext->stream);
    nabto_device_future_wait(fut);
    nabto_device_future_free(fut);
    nabto_device_stream_free(streamContext->stream);
    free(streamContext);
}

void stream_read_callback(NabtoDeviceFuture* fut, NabtoDeviceError err, void* data)
{
    struct streamContext* streamContext = (struct streamContext*)data;
    nabto_device_future_free(fut);
    if (err == NABTO_DEVICE_EC_FAILED) {
        printf("stream closed or aborted" NEWLINE);
        close_stream(streamContext);
        return;
    }
    printf("read %lu bytes into buf:", streamContext->readen);
    printf("%s" NEWLINE, streamContext->buffer);

    fut = nabto_device_stream_write(streamContext->stream, streamContext->buffer, streamContext->readen);
    nabto_device_future_wait(fut);
    if (nabto_device_future_error_code(fut) != NABTO_DEVICE_EC_OK) {
        printf("stream write failed" NEWLINE);
        close_stream(streamContext);
        return;
    }
    nabto_device_future_free(fut);
    memset(streamContext->buffer, 0, 1500);
    fut = nabto_device_stream_read_some(streamContext->stream, streamContext->buffer, 1500, &streamContext->readen);
    nabto_device_future_set_callback(fut, &stream_read_callback, streamContext);
}

void handle_new_stream(struct streamContext* streamContext)
{
    NabtoDeviceFuture* fut = nabto_device_stream_accept(streamContext->stream);
    nabto_device_future_wait(fut);
    if (nabto_device_future_error_code(fut) != NABTO_DEVICE_EC_OK) {
        printf("stream accept failed, dropping stream");
        nabto_device_stream_free(streamContext->stream);
        free(streamContext);
        return;
    }
    fut = nabto_device_stream_read_some(streamContext->stream, streamContext->buffer, 1500, &streamContext->readen);
    nabto_device_future_set_callback(fut, &stream_read_callback, streamContext);
}

void run_device()
{
    NabtoDeviceError ec;
    NabtoDeviceStream* stream;
    NabtoDevice* dev = nabto_device_new();
    nabto_device_set_std_out_log_callback();
    ec = nabto_device_set_public_key(dev, config.crtPemBuffer);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    ec = nabto_device_set_private_key(dev, config.keyPemBuffer);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    ec = nabto_device_set_server_url(dev, config.hostname);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }
    ec = nabto_device_start(dev);
    if (ec != NABTO_DEVICE_EC_OK) {
        return;
    }

    nabto_device_coap_add_resource(dev, NABTO_DEVICE_COAP_GET, "/test/get", &handle_coap_get_request, dev);
    nabto_device_coap_add_resource(dev, NABTO_DEVICE_COAP_POST, "/test/post", &handle_coap_post_request, dev);

    // wait for ctrl-c
    while (true) {
        NabtoDeviceFuture* fut = nabto_device_stream_listen(dev, &stream);
        nabto_device_future_wait(fut);
        if (nabto_device_future_error_code(fut) != NABTO_DEVICE_EC_OK) {
            printf("Stream listen returned with an error");
            return;
        }
        nabto_device_future_free(fut);
        struct streamContext* strCtx = malloc(sizeof(struct streamContext));
        strCtx->stream = stream;
        handle_new_stream(strCtx);
    }
}

int main(int argc, const char** argv)
{
    memset(&config, 0, sizeof(struct config));
    if (!parse_args(argc, argv)) {
        exit(1);
    }

    if (!file_exists(config.keyFile)) {
        // TODO generate key with this application.
        printf("Missing keyfile." NEWLINE);
        printf("Generate a new keyfile with: openssl ecparam -genkey -name prime256v1 -out <filename>.pem" NEWLINE);
        exit(1);
    }

    if (!load_key_from_file(config.keyFile)) {
        printf("Keyfile could not be read" NEWLINE);
        exit(1);
    }

    if (!create_pem_cert(config.keyPemBuffer)) {
        printf("could not create crt container for the public key." NEWLINE);
        exit(1);
    }

    uint8_t* f = config.deviceFingerprint;
    printf("Starting device productid: %s, deviceid: %s, fingerprint: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x" NEWLINE, config.productId, config.deviceId,
           f[0], f[1], f[2],  f[3],  f[4],  f[5],  f[6],  f[7],
           f[8], f[9], f[10], f[11], f[12], f[13], f[14], f[15]);

    printf("%s" NEWLINE, config.keyPemBuffer);
    printf("%s" NEWLINE, config.crtPemBuffer);

    run_device();

    // TODO start a device
    // TODO add streaming and coap handlers

}
