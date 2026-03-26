//go:build darwin && cgo

package platform

/*
#cgo LDFLAGS: -framework LocalAuthentication
#include "biometric_darwin.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

func touchIDPrompt(reason string) error {
	cReason := C.CString(reason)
	defer C.free(unsafe.Pointer(cReason))

	r := C.biometric_prompt(cReason)
	defer C.biometric_result_free(&r)

	if r.ok != 1 {
		if r.err != nil {
			return fmt.Errorf("touch id: %s", C.GoString(r.err))
		}
		return fmt.Errorf("touch id verification failed")
	}
	return nil
}

func touchIDAvailable() bool {
	return C.biometric_available() == 1
}
