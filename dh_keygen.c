#include "header/dh_keygen.h"
#include <openssl/dh.h>
#include <openssl/pem.h>

int generate_dh_key_pair(EVP_PKEY** my_privkey) {
    EVP_PKEY* dh_params = EVP_PKEY_new();
    if (!dh_params) {
        return -1;
    }

    DH* low_params = DH_get_2048_224();
    if (!EVP_PKEY_set1_DH(dh_params, low_params)) {
        DH_free(low_params);
        EVP_PKEY_free(dh_params);
        return -1;
    }
    DH_free(low_params);

    EVP_PKEY_CTX* dh_ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    if (!dh_ctx) {
        EVP_PKEY_free(dh_params);
        return -1;
    }

    if (!EVP_PKEY_keygen_init(dh_ctx)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_ctx);
        return -1;
    }

    if (!EVP_PKEY_keygen(dh_ctx, my_privkey)) {
        EVP_PKEY_free(dh_params);
        EVP_PKEY_CTX_free(dh_ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(dh_ctx);
    EVP_PKEY_free(dh_params);

    return 0;
}

int write_public_key_to_file(EVP_PKEY* my_privkey, const char* filename) {
    FILE* fptr = fopen(filename, "w+");
    if (fptr == NULL) {
        printf("The file is not opened. The program will now exit.");
        return -1;
    }

    if (PEM_write_PUBKEY(fptr, my_privkey) != 1) {
        printf("Errore nella generazione delle chiavi DH del client");
        fclose(fptr);
        return -1;
    }

    fclose(fptr);
    return 0;
}