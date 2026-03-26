// Secure Enclave seal/unseal for macOS.
//
// Uses a persistent P-256 key in the Secure Enclave (T2 / Apple Silicon)
// stored in the Keychain under a fixed application tag. Data is encrypted
// with ECIES (X9.63 KDF + AES-GCM) using the SE key's public half;
// decryption uses the private half which never leaves the hardware.

#include "enclave_darwin.h"

#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

static const char *kKeyTag = "com.kvstore.enclave-key";

// ECIES with cofactor ECDH, X9.63 SHA-256 KDF, AES-256-GCM.
static const SecKeyAlgorithm kAlgo =
    kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// cf_error_string extracts a C string from a CFErrorRef and releases it.
static char *cf_error_string(CFErrorRef err) {
    if (err == NULL) return strdup("unknown error");

    CFStringRef desc = CFErrorCopyDescription(err);
    CFRelease(err);
    if (desc == NULL) return strdup("unknown error");

    CFIndex maxLen = CFStringGetMaximumSizeForEncoding(
        CFStringGetLength(desc), kCFStringEncodingUTF8) + 1;
    char *buf = (char *)malloc((size_t)maxLen);
    if (!CFStringGetCString(desc, buf, maxLen, kCFStringEncodingUTF8)) {
        // Fallback: if conversion fails, just note the failure.
        CFRelease(desc);
        free(buf);
        return strdup("secure enclave operation failed");
    }
    CFRelease(desc);
    return buf;
}

// ---------------------------------------------------------------------------
// Keychain key management
// ---------------------------------------------------------------------------

// find_key looks up the SE key in the Keychain by its application tag.
static SecKeyRef find_key(void) {
    CFDataRef tag = CFDataCreate(
        NULL, (const UInt8 *)kKeyTag, (CFIndex)strlen(kKeyTag));

    const void *keys[] = {
        kSecClass, kSecAttrApplicationTag,
        kSecAttrKeyType, kSecReturnRef,
    };
    const void *vals[] = {
        kSecClassKey, tag,
        kSecAttrKeyTypeECSECPrimeRandom, kCFBooleanTrue,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        NULL, keys, vals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching(query, (CFTypeRef *)&key);

    CFRelease(tag);
    CFRelease(query);

    return (status == errSecSuccess) ? key : NULL;
}

// create_key generates a new P-256 key inside the Secure Enclave.
// The key is stored permanently in the Keychain.
static SecKeyRef create_key(CFErrorRef *errOut) {
    CFErrorRef error = NULL;

    // Access control: usable when device is unlocked, this device only,
    // private key operations allowed. No biometric constraint — any process
    // running as the current user can use the key (same model as TPM SRK).
    SecAccessControlRef acl = SecAccessControlCreateWithFlags(
        NULL,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlPrivateKeyUsage,
        &error);
    if (acl == NULL) {
        if (errOut) *errOut = error;
        return NULL;
    }

    CFDataRef tag = CFDataCreate(
        NULL, (const UInt8 *)kKeyTag, (CFIndex)strlen(kKeyTag));

    // Private key attributes — permanent, tagged, access-controlled.
    const void *privKeys[] = {
        kSecAttrIsPermanent, kSecAttrApplicationTag, kSecAttrAccessControl,
    };
    const void *privVals[] = {
        kCFBooleanTrue, tag, acl,
    };
    CFDictionaryRef privAttrs = CFDictionaryCreate(
        NULL, privKeys, privVals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    int bits = 256;
    CFNumberRef keySize = CFNumberCreate(NULL, kCFNumberIntType, &bits);

    // Key generation parameters.
    const void *paramKeys[] = {
        kSecAttrKeyType, kSecAttrKeySizeInBits,
        kSecAttrTokenID, kSecPrivateKeyAttrs,
    };
    const void *paramVals[] = {
        kSecAttrKeyTypeECSECPrimeRandom, keySize,
        kSecAttrTokenIDSecureEnclave, privAttrs,
    };
    CFDictionaryRef params = CFDictionaryCreate(
        NULL, paramKeys, paramVals, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    SecKeyRef key = SecKeyCreateRandomKey(params, &error);

    CFRelease(params);
    CFRelease(privAttrs);
    CFRelease(keySize);
    CFRelease(tag);
    CFRelease(acl);

    if (key == NULL && errOut) *errOut = error;
    return key;
}

// get_or_create_key returns the existing SE key or creates a new one.
static SecKeyRef get_or_create_key(CFErrorRef *errOut) {
    SecKeyRef key = find_key();
    if (key != NULL) return key;
    return create_key(errOut);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

int enclave_available(void) {
    // Check for the Secure Enclave Processor via IOKit. Present on all
    // Apple Silicon Macs and T2-equipped Intel Macs.
    // Using 0 for the port avoids deprecation of kIOMasterPortDefault
    // while being equivalent to kIOMainPortDefault (macOS 12+).
    io_service_t svc = IOServiceGetMatchingService(
        0, IOServiceMatching("AppleSEPManager"));
    if (svc == IO_OBJECT_NULL) return 0;
    IOObjectRelease(svc);
    return 1;
}

enclave_result_t enclave_seal(const void *data, int len) {
    enclave_result_t r = {NULL, 0, NULL};
    CFErrorRef error = NULL;

    SecKeyRef privKey = get_or_create_key(&error);
    if (privKey == NULL) {
        r.err = cf_error_string(error);
        return r;
    }

    SecKeyRef pubKey = SecKeyCopyPublicKey(privKey);
    CFRelease(privKey);
    if (pubKey == NULL) {
        r.err = strdup("failed to copy public key from secure enclave key");
        return r;
    }

    CFDataRef plaintext = CFDataCreate(NULL, (const UInt8 *)data, (CFIndex)len);
    CFDataRef ciphertext = SecKeyCreateEncryptedData(
        pubKey, kAlgo, plaintext, &error);
    CFRelease(pubKey);
    CFRelease(plaintext);

    if (ciphertext == NULL) {
        r.err = cf_error_string(error);
        return r;
    }

    r.len = (int)CFDataGetLength(ciphertext);
    r.data = malloc((size_t)r.len);
    memcpy(r.data, CFDataGetBytePtr(ciphertext), (size_t)r.len);
    CFRelease(ciphertext);
    return r;
}

enclave_result_t enclave_unseal(const void *data, int len) {
    enclave_result_t r = {NULL, 0, NULL};
    CFErrorRef error = NULL;

    SecKeyRef privKey = find_key();
    if (privKey == NULL) {
        r.err = strdup("secure enclave key not found in keychain");
        return r;
    }

    CFDataRef ciphertext = CFDataCreate(NULL, (const UInt8 *)data, (CFIndex)len);
    CFDataRef plaintext = SecKeyCreateDecryptedData(
        privKey, kAlgo, ciphertext, &error);
    CFRelease(privKey);
    CFRelease(ciphertext);

    if (plaintext == NULL) {
        r.err = cf_error_string(error);
        return r;
    }

    r.len = (int)CFDataGetLength(plaintext);
    r.data = malloc((size_t)r.len);
    memcpy(r.data, CFDataGetBytePtr(plaintext), (size_t)r.len);
    CFRelease(plaintext);
    return r;
}

void enclave_result_free(enclave_result_t *r) {
    if (r == NULL) return;
    if (r->data != NULL) {
        free(r->data);
        r->data = NULL;
    }
    if (r->err != NULL) {
        free(r->err);
        r->err = NULL;
    }
}
