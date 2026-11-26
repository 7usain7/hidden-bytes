//go:build !windows

package main

import "fmt"

func runPEInMemory(pe []byte) error {
	return fmt.Errorf("in-memory PE execution only supported on Windows")
}
