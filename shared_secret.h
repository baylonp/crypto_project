#ifndef SHARED_SECRET_H
#define SHARED_SECRET_H

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

// Function to derive a shared secret
unsigned char* derive_shared_secret(EVP_PKEY* my_privkey, EVP_PKEY* peer_pub_key, size_t* secret_len);

#endif // SHARED_SECRET_H
