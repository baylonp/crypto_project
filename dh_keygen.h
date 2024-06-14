#ifndef DH_KEYGEN_H
#define DH_KEYGEN_H

#include <openssl/evp.h>
#include <stdio.h>

// Function to generate DH key pair
int generate_dh_key_pair(EVP_PKEY** my_privkey);

// Function to write the public key to a PEM file
int write_public_key_to_file(EVP_PKEY* my_privkey, const char* filename);

#endif // DH_KEYGEN_H
