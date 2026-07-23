//go:build ignore

// Command generate_bloom encodes a normalized, one-hostname-per-line CrUX
// snapshot as the compact Bloom filter embedded by the checker.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
)

const (
	bloomBits     = uint64(2_879_003)
	bloomHashes   = uint64(20)
	wantHostCount = 99_946
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run generate_bloom.go <normalized-hostnames.txt>")
		os.Exit(2)
	}
	input, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer input.Close()

	bits := make([]byte, (bloomBits+7)/8)
	seen := make(map[string]struct{}, wantHostCount)
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(scanner.Text())), ".")
		if host == "" {
			continue
		}
		if _, exists := seen[host]; exists {
			continue
		}
		seen[host] = struct{}{}
		add(bits, host)
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	if len(seen) != wantHostCount {
		panic(fmt.Sprintf("hostname count %d, want %d", len(seen), wantHostCount))
	}

	if _, err := os.Stdout.Write(bits); err != nil {
		panic(err)
	}
}

func add(bits []byte, host string) {
	digest := sha256.Sum256([]byte(host))
	first := binary.LittleEndian.Uint64(digest[:8]) % bloomBits
	step := binary.LittleEndian.Uint64(digest[8:16]) % bloomBits
	if step == 0 {
		step = 1
	}
	for index := uint64(0); index < bloomHashes; index++ {
		bit := (first + index*step) % bloomBits
		bits[bit/8] |= 1 << uint(bit%8)
	}
}
