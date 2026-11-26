package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"evan/internal/builder"
	"evan/internal/crypto"
	"evan/internal/runner"
)

const usageText = `Evan Program Usage:
  --encrypt <target-file>     encrypt a file and produce a self-contained binary
  --output <name>             name of the produced binary (default: <target>_enc)
  --run <enc> <key>           decrypt and execute a payload (uses .enc + .key on disk)
  --add-size <size-in-mb>     pad the produced binary by N MB
  --delay <seconds>           delay execution by N seconds`

type nonNegFloat float64

func (n *nonNegFloat) String() string { return strconv.FormatFloat(float64(*n), 'f', -1, 64) }
func (n *nonNegFloat) Set(s string) error {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return fmt.Errorf("invalid number: %q", s)
	}
	if v < 0 {
		return fmt.Errorf("must be a non-negative number")
	}
	*n = nonNegFloat(v)
	return nil
}

func main() {
	flag.Usage = func() { fmt.Println(usageText) }

	encryptFlag := flag.String("encrypt", "", "target file")
	outputFlag := flag.String("output", "", "output binary name")
	runFlag := flag.Bool("run", false, "decrypt and execute a payload")
	helpFlag := flag.Bool("help", false, "show help")
	var addSize, delay nonNegFloat
	flag.Var(&addSize, "add-size", "size in MB")
	flag.Var(&delay, "delay", "seconds")

	flag.Parse()

	if *helpFlag || len(os.Args) < 2 {
		fmt.Println(usageText)
		return
	}

	// Mode 1: decrypt-and-run from .enc + .key on disk.
	if *runFlag {
		pos := flag.Args()
		if len(pos) < 2 {
			fmt.Fprintln(os.Stderr, "usage: evan --run <encrypted_path> <key_path> [payload args...]")
			os.Exit(2)
		}
		if delay > 0 {
			time.Sleep(time.Duration(float64(delay) * float64(time.Second)))
		}
		if err := runner.RunEncrypted(pos[0], pos[1], pos[2:]); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				os.Exit(ee.ExitCode())
			}
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Mode 2: encrypt and produce a self-contained binary.
	if *encryptFlag != "" {
		target := *encryptFlag
		info, err := os.Stat(target)
		if err != nil || info.IsDir() {
			fmt.Fprintf(os.Stderr, "Error: target file not found: %s\n", target)
			os.Exit(1)
		}

		// Default .enc/.key paths stay next to the target — useful for --run testing.
		encPath := target + ".enc"
		blob, key, err := crypto.EncryptFile(target, encPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Encrypted %s -> %s\n", target, encPath)
		fmt.Printf("Key (hex): %s\n", hex.EncodeToString(key))

		// Determine binary name.
		binName := *outputFlag
		if binName == "" {
			binName = filepath.Base(target) + "_enc"
		}
		// Safety: refuse to overwrite the source.
		if abs, _ := filepath.Abs(binName); abs == mustAbs(target) {
			fmt.Fprintf(os.Stderr, "Error: refusing to overwrite source file %q\n", target)
			os.Exit(1)
		}

		fmt.Printf("\nCompiling self-contained binary %q ...\n", binName)
		if err := builder.CompileSelfContained(blob, key, binName, ".", float64(addSize), float64(delay)); err != nil {
			fmt.Fprintf(os.Stderr, "Compile error: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Done: ./%s  (run it with no arguments)\n", binName)
		return
	}

	// Mode 3: info.
	fmt.Println("Parsed arguments:")
	fmt.Printf("  encrypt : %s\n", *encryptFlag)
	fmt.Printf("  output  : %s\n", *outputFlag)
	fmt.Printf("  add_size: %v\n", float64(addSize))
	fmt.Printf("  delay   : %v\n", float64(delay))
}

func mustAbs(p string) string {
	a, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	return a
}
