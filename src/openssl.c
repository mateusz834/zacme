#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

EVP_PKEY *gen_RSA(unsigned int bits) {
	return EVP_RSA_gen(bits);
}

EVP_PKEY *gen_ECDSA(const char* curve) {
	return EVP_EC_gen(curve);
}
