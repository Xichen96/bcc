package main

// #cgo LDFLAGS: -ldl
import "C"
import (
	"unsafe"
)

func nilPtr() unsafe.Pointer {
	return unsafe.Pointer(uintptr(0))
}

func nilStrPtr() *C.char {
	return (*C.char)(nilPtr())
}

func nilStrArrPtr() **C.char {
	return (**C.char)(nilPtr())
}

func cString(s string) *C.char {
	if len(s) == 0 {
		return nilStrPtr()
	} else {
		return C.CString(s)
	}
}

func goString(c *C.char) string {
	if unsafe.Pointer(c) == unsafe.Pointer(uintptr(0)) {
		return ""
	}
	return C.GoString(c)
}

func ptrTo64(ptr *uintptr) *uint64 {
	p := uint64(*ptr)
	return &p
}

