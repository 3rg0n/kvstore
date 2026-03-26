// Touch ID biometric verification for macOS.
//
// Uses LAContext from LocalAuthentication.framework to prompt for
// fingerprint verification via Touch ID. Falls back gracefully when
// no biometric hardware is present.

#include "biometric_darwin.h"

#import <LocalAuthentication/LocalAuthentication.h>
#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>

int biometric_available(void) {
    LAContext *context = [[LAContext alloc] init];
    BOOL ok = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                   error:nil];
    [context release];
    return ok ? 1 : 0;
}

biometric_result_t biometric_prompt(const char *reason) {
    __block biometric_result_t r = {0, NULL};

    LAContext *context = [[LAContext alloc] init];
    NSError *error = nil;

    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                              error:&error]) {
        if (error) {
            r.err = strdup([[error localizedDescription] UTF8String]);
        } else {
            r.err = strdup("biometric authentication not available");
        }
        [context release];
        return r;
    }

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
           localizedReason:[NSString stringWithUTF8String:reason]
                     reply:^(BOOL ok, NSError *authError) {
        if (ok) {
            r.ok = 1;
        } else {
            if (authError) {
                r.err = strdup([[authError localizedDescription] UTF8String]);
            } else {
                r.err = strdup("touch id verification denied");
            }
        }
        dispatch_semaphore_signal(sem);
    }];

    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_release(sem);
    [context release];

    return r;
}

void biometric_result_free(biometric_result_t *r) {
    if (r == NULL) return;
    if (r->err != NULL) {
        free(r->err);
        r->err = NULL;
    }
}
