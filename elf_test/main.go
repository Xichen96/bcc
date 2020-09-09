package main

// #include <bcc/bcc_common.h>
// #include <bcc/libbpf.h>
// #include <bcc/bcc_proc.h>
// #include <bcc/bcc_syms.h>
// #cgo CFLAGS: -I/usr/include -Wno-error=implicit-function-declaration
// #cgo LDFLAGS: -L/usr/lib/x86_64-linux-gnu -lbcc
import "C"
import (
	"fmt"
	"unsafe"
	//"io/ioutil"
	"log"
)

func LIBBCC_bpf_elf_create_b(filename string, proto_file_name string, flags uint, dev_name string, elf_path string) int {
	cs_filename := cString(filename)
	defer C.free(unsafe.Pointer(cs_filename))
	cs_proto_file_name := cString(proto_file_name)
	defer C.free(unsafe.Pointer(cs_proto_file_name))
	cs_dev_name := cString(dev_name)
	defer C.free(unsafe.Pointer(cs_dev_name))
	cs_elf_path := cString(dev_name)
	defer C.free(unsafe.Pointer(cs_elf_path))
	return int(C.bpf_elf_create_b(cs_filename, cs_proto_file_name, C.uint(flags), cs_dev_name, cs_elf_path))
}

func LIBBCC_bpf_elf_create_c(filename string, flags uint, cflags []string, ncflags int, allow_rlimit bool, dev_name string, elf_path string) int {
	cs_filename := cString(filename)
	defer C.free(unsafe.Pointer(cs_filename))
	cs_cflags := make([]*C.char, 0)
	for _, s := range cflags {
		cs_s := cString(s)
		cs_cflags = append(cs_cflags, cs_s)
	}
	defer func() {
		for _, cs_s := range cs_cflags {
			C.free(unsafe.Pointer(cs_s))
		}
	}()
	cs_dev_name := cString(dev_name)
	defer C.free(unsafe.Pointer(cs_dev_name))
	cs_elf_path := cString(elf_path)
	defer C.free(unsafe.Pointer(cs_elf_path))
	if ncflags > 0 {
		return int(C.bpf_elf_create_c(cs_filename, C.uint(flags), &cs_cflags[0], C.int(ncflags), C.bool(allow_rlimit), cs_dev_name, cs_elf_path))
	} else {
		return int(C.bpf_elf_create_c(cs_filename, C.uint(flags), nilStrArrPtr(), C.int(ncflags), C.bool(allow_rlimit), cs_dev_name, cs_elf_path))
	}
}

func LIBBCC_bpf_elf_create_c_from_string(text string, flags uint, cflags []string, ncflags int, allow_rlimit bool, dev_name string, elf_path string) int {
	cs_text := cString(text)
	defer C.free(unsafe.Pointer(cs_text))
	cs_cflags := make([]*C.char, 0)
	for _, s := range cflags {
		cs_s := cString(s)
		cs_cflags = append(cs_cflags, cs_s)
	}
	defer func() {
		for _, cs_s := range cs_cflags {
			C.free(unsafe.Pointer(cs_s))
		}
	}()
	cs_dev_name := cString(dev_name)
	defer C.free(unsafe.Pointer(cs_dev_name))
	cs_elf_path := cString(elf_path)
	defer C.free(unsafe.Pointer(cs_elf_path))
	if ncflags > 0 {
		return int(C.bpf_elf_create_c_from_string(cs_text, C.uint(flags), &cs_cflags[0], C.int(ncflags), C.bool(allow_rlimit), cs_dev_name, cs_elf_path))
	} else {
		return int(C.bpf_elf_create_c_from_string(cs_text, C.uint(flags), nilStrArrPtr(), C.int(ncflags), C.bool(allow_rlimit), cs_dev_name, cs_elf_path))
	}
}

func CompileELF(text string, path string) error {
	ret := LIBBCC_bpf_elf_create_c_from_string(text, uint(0), make([]string, 0), 0, true, "", path)
	if ret == 0 {
		return nil
	}
	return fmt.Errorf("create elf failed")
}

func CompileELFFromFile(textPath string, path string) error {
	args := make([]string, 0)
	args = append(args, "-I/elf_test/bpf", "-I/katran/katran/lib/linux_includes",  "-I/usr/local/lib/clang/12.0.0/include/")
	//args = append(args, "-I/usr/local/lib/clang/12.0.0/include")
	//args = append(args, "-I")
	ret := LIBBCC_bpf_elf_create_c(textPath, uint(0), args, len(args), true, "", path)
	if ret == 0 {
		return nil
	}
	return fmt.Errorf("create elf failed")
}

/*
func main() {
	content, err := ioutil.ReadFile("/elf_test/text.c")
	if err != nil {
		log.Fatalf("read file failed: %v\n", err)
	}
	err = CompileELF(string(content), "/elf_test/elf")
	if err != nil {
		log.Fatalf("compile elf failed: %v", err)
	}
}
*/

func main() {
	err := CompileELFFromFile("/elf_test/bpf/xdp_root.c", "/elf_test/elf")
	if err != nil {
		log.Fatalf("compile elf failed: %v", err)
	}
}
