#include <openssl/rsa.h>

EVP_PKEY *gen_RSA(unsigned int bits);
EVP_PKEY *gen_ECDSA(const char* curve);
void load_crypto_err_strings();
