#include <openssl/rsa.h>
#include <openssl/asn1t.h>

EVP_PKEY *gen_RSA(unsigned int bits);
EVP_PKEY *gen_ECDSA(const char* curve);
void load_crypto_err_strings();

int add_SANs(X509_REQ* req, const char* sans);
