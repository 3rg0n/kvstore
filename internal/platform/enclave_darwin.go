//go:build darwin && cgo

package platform

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -framework IOKit
#include "enclave_darwin.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

func enclaveSeal(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("cannot seal empty data")
	}
	r := C.enclave_seal(unsafe.Pointer(&data[0]), C.int(len(data)))
	defer C.enclave_result_free(&r)
	if r.err != nil {
		return nil, fmt.Errorf("secure enclave seal: %s", C.GoString(r.err))
	}
	if r.data == nil {
		return nil, errors.New("secure enclave seal returned empty result")
	}
	return C.GoBytes(r.data, r.len), nil
}

func enclaveUnseal(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, errors.New("cannot unseal empty data")
	}
	r := C.enclave_unseal(unsafe.Pointer(&sealed[0]), C.int(len(sealed)))
	defer C.enclave_result_free(&r)
	if r.err != nil {
		return nil, fmt.Errorf("secure enclave unseal: %s", C.GoString(r.err))
	}
	if r.data == nil {
		return nil, errors.New("secure enclave unseal returned empty result")
	}
	return C.GoBytes(r.data, r.len), nil
}

func enclaveAvailable() bool {
	return C.enclave_available() == 1
}
