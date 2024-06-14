#ifndef DH_UTILS_H
#define DH_UTILS_H

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "struct.h"

// Function to read a private key from a file
EVP_PKEY* read_private_key(const char* filename);

// Function to read a public key from a file
EVP_PKEY* read_public_key(const char* filename);

// Function to compute SHA-256 hash of a plaintext
unsigned char* compute_sha256(const unsigned char* plaintext, size_t length, unsigned char* hash);

// Funzioni di firma e verifica
int sign_data(const unsigned char *data, int data_len, unsigned char **signature, size_t *signature_len, EVP_PKEY *rsa_private_key);
int verify_signature(const unsigned char *data, int data_len, const unsigned char *signature, size_t signature_len, EVP_PKEY *rsa_public_key);



#endif // DH_UTILS_H