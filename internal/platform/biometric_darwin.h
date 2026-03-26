#ifndef BIOMETRIC_DARWIN_H
#define BIOMETRIC_DARWIN_H

// biometric_result holds the outcome of a Touch ID prompt.
// Caller must call biometric_result_free to release memory.
typedef struct {
    int   ok;   // 1 on success, 0 on failure
    char *err;  // error string (malloc'd) or NULL on success
} biometric_result_t;

// biometric_available returns 1 if Touch ID hardware is present and enrolled.
int biometric_available(void);

// biometric_prompt shows the Touch ID dialog with the given reason string.
// Blocks until the user verifies or cancels.
biometric_result_t biometric_prompt(const char *reason);

// biometric_result_free releases memory owned by a biometric_result_t.
void biometric_result_free(biometric_result_t *r);

#endif
