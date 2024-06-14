#include "header/shared_secret.h"

unsigned char* derive_shared_secret(EVP_PKEY* my_privkey, EVP_PKEY* peer_pub_key, size_t* secret_len) {
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(my_privkey, NULL);
    if (!ctx_drv) {
        printf("Context initialization failure.\n");
        return NULL;
    }

    if (EVP_PKEY_derive_init(ctx_drv) <= 0) {
        printf("Derive initialization failure.\n");
        EVP_PKEY_CTX_free(ctx_drv);
        return NULL;
    }

    if (EVP_PKEY_derive_set_peer(ctx_drv, peer_pub_key) <= 0) {
        printf("Setting peer key failure.\n");
        EVP_PKEY_CTX_free(ctx_drv);
        return NULL;
    }

    if (EVP_PKEY_derive(ctx_drv, NULL, secret_len) <= 0) {
        printf("Getting secret length failure.\n");
        EVP_PKEY_CTX_free(ctx_drv);
        return NULL;
    }

    unsigned char* secret = (unsigned char*)malloc(*secret_len);
    if (!secret) {
        printf("Memory allocation failure.\n");
        EVP_PKEY_CTX_free(ctx_drv);
        return NULL;
    }

    if (EVP_PKEY_derive(ctx_drv, secret, secret_len) <= 0) {
        printf("Secret derivation failure.\n");
        free(secret);
        EVP_PKEY_CTX_free(ctx_drv);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx_drv);
    return secret;
}