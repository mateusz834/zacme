#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

EVP_PKEY *gen_RSA(unsigned int bits) {
	return EVP_RSA_gen(bits);
}

EVP_PKEY *gen_ECDSA(const char* curve) {
	return EVP_EC_gen(curve);
}

void load_crypto_err_strings() {
	ERR_load_crypto_strings();
}

int add_SANs(X509_REQ* req, const char* sans) {
	STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

	if (add_ext(exts, NID_subject_alt_name, sans) <= 0) {
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		return 0;
	}

	if (X509_REQ_add_extensions(req, exts) <= 0) {
		sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
		return 0;
	}

	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return 1;
};

int add_ext(STACK_OF(X509_EXTENSION) *sk, int nid, char *value) {
	X509_EXTENSION *ex;
	ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
	if (!ex) {
	        return 0;
	}
	sk_X509_EXTENSION_push(sk, ex);
	return 1;
}
