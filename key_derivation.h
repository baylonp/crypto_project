#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to derive the AES-128 key from the shared secret
unsigned char* derive_aes_key(const unsigned char* secret, size_t secret_len, unsigned int* key_len);

#endif // KEY_DERIVATION_H


