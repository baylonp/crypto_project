#include "header/crypto_utils.h"

int password_callback(char *buf, int size, int rwflag, void *userdata) {
    const char *password = "password"; // Replace this with your actual password
    strncpy(buf, password, size);
    buf[size - 1] = '\0'; // Ensure null-terminated string
    return strlen(password);
}


EVP_PKEY* read_private_key(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;
    }
    
    EVP_PKEY* private_key = PEM_read_PrivateKey(fp, NULL, password_callback, NULL);
    fclose(fp);
    
    if (!private_key) {
        fprintf(stderr, "Unable to read private key from %s\n", filename);
    }
    
    return private_key;
}


EVP_PKEY* read_public_key(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Unable to open file %s\n", filename);
        return NULL;
    }
    
    EVP_PKEY* public_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!public_key) {
        fprintf(stderr, "Unable to read public key from %s\n", filename);
    }
    
    return public_key;
}



unsigned char* compute_sha256(const unsigned char* plaintext, size_t length, unsigned char* hash) {
    SHA256_CTX sha256;
    if (!SHA256_Init(&sha256)) {
        fprintf(stderr, "SHA256_Init failed\n");
        return NULL;
    }
    if (!SHA256_Update(&sha256, plaintext, length)) {
        fprintf(stderr, "SHA256_Update failed\n");
        return NULL;
    }
    if (!SHA256_Final(hash, &sha256)) {
        fprintf(stderr, "SHA256_Final failed\n");
        return NULL;
    }
    return hash;
}

int sign_data(const unsigned char *data, int data_len, unsigned char **signature, size_t *signature_len, EVP_PKEY *rsa_private_key) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return 0; // Error
    }

    // Hash the data
    if (!EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, rsa_private_key)) {
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    if (!EVP_DigestSignUpdate(md_ctx, data, data_len)) {
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    // Get the length of the signature
    if (!EVP_DigestSignFinal(md_ctx, NULL, signature_len)) {
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    // Allocate memory for the signature
    *signature = (unsigned char *)malloc(*signature_len);
    if (*signature == NULL) {
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    // Perform the actual signing
    if (!EVP_DigestSignFinal(md_ctx, *signature, signature_len)) {
        free(*signature);
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    EVP_MD_CTX_free(md_ctx);
    return 1; // Success
}


int verify_signature(const unsigned char *data, int data_len, const unsigned char *signature, size_t signature_len, EVP_PKEY *rsa_public_key) {
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        return 0; // Error
    }

    // Hash the data
    if (!EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, rsa_public_key)) {
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    if (!EVP_DigestVerifyUpdate(md_ctx, data, data_len)) {
        EVP_MD_CTX_free(md_ctx);
        return 0; // Error
    }

    // Perform the actual verification
    int result = EVP_DigestVerifyFinal(md_ctx, signature, signature_len);

    EVP_MD_CTX_free(md_ctx);
    return result; // 1 if the signature is valid, 0 otherwise
}
