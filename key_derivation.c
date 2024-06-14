#include "header/key_derivation.h"

unsigned char* derive_aes_key(const unsigned char* secret, size_t secret_len, unsigned int* key_len) {
    unsigned char* full_k_ab = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if (!full_k_ab) return NULL;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        free(full_k_ab);
        return NULL;
    }

    if (!EVP_DigestInit(ctx, EVP_sha256()) ||
        !EVP_DigestUpdate(ctx, secret, secret_len) ||
        !EVP_DigestFinal(ctx, full_k_ab, key_len)) {
        EVP_MD_CTX_free(ctx);
        free(full_k_ab);
        return NULL;
    }

    EVP_MD_CTX_free(ctx);

    //  //sha 256 genera 256 bit di chiave, sono troppi per l'aes a 128 bit--> quindi tronchiamo
    // Truncate to AES-128 key length
    unsigned char* k_ab = (unsigned char*)malloc(EVP_CIPHER_key_length(EVP_aes_128_gcm()));
    if (!k_ab) {
        free(full_k_ab);
        return NULL;
    }

    if (*key_len > (unsigned int)EVP_CIPHER_key_length(EVP_aes_128_gcm())) {
        memcpy(k_ab, full_k_ab, EVP_CIPHER_key_length(EVP_aes_128_gcm()));
        *key_len = EVP_CIPHER_key_length(EVP_aes_128_gcm());
    } else {
        memcpy(k_ab, full_k_ab, *key_len);
    }

    free(full_k_ab);
    return k_ab;
}