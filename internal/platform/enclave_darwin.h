#ifndef ENCLAVE_DARWIN_H
#define ENCLAVE_DARWIN_H

#include <stdint.h>

// enclave_result holds the output of seal/unseal operations.
// Caller must call enclave_result_free to release memory.
typedef struct {
    void *data;  // output bytes (malloc'd) or NULL
    int   len;   // output length
    char *err;   // error string (malloc'd) or NULL on success
} enclave_result_t;

// enclave_available returns 1 if the Secure Enclave is present, 0 otherwise.
int enclave_available(void);

// enclave_seal encrypts data using a Secure Enclave-backed P-256 key.
// Creates the key on first use (stored in Keychain with fixed tag).
enclave_result_t enclave_seal(const void *data, int len);

// enclave_unseal decrypts data previously encrypted by enclave_seal.
enclave_result_t enclave_unseal(const void *data, int len);

// enclave_result_free releases memory owned by an enclave_result_t.
void enclave_result_free(enclave_result_t *r);

#endif
