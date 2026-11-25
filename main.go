package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	keySize   = 32
	nonceSize = 12
	tagSize   = 16
)

const usageText = `Evan Program Usage:
  --encrypt <target-file>     encrypt a file and produce a self-contained binary
  --output <name>             name of the produced binary (default: <target>_enc)
  --run <enc> <key>           decrypt and execute a payload (uses .enc + .key on disk)
  --add-size <size-in-mb>     (reserved)
  --delay <seconds>           (reserved)`

// ---------------------------------------------------------------------------
// AES-256-GCM. On-disk format: nonce (12) || tag (16) || ciphertext
// ---------------------------------------------------------------------------

// encryptFile writes the encrypted blob + .key file and returns the blob
// (nonce ‖ tag ‖ ciphertext) plus the raw key.
func encryptFile(targetPath, outputPath string) ([]byte, []byte, error) {
	plaintext, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, nil, err
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	sealed := gcm.Seal(nil, nonce, plaintext, nil) // ciphertext ‖ tag
	ct := sealed[:len(sealed)-tagSize]
	tag := sealed[len(sealed)-tagSize:]

	blob := make([]byte, 0, nonceSize+tagSize+len(ct))
	blob = append(blob, nonce...)
	blob = append(blob, tag...)
	blob = append(blob, ct...)

	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(outputPath, blob, 0o644); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(outputPath+".key", []byte(hex.EncodeToString(key)), 0o644); err != nil {
		return nil, nil, err
	}
	return blob, key, nil
}

func decryptFile(encryptedPath, keyPath string) ([]byte, error) {
	keyHex, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", keySize, len(key))
	}

	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, err
	}
	return decryptBlob(data, key)
}

func decryptBlob(data, key []byte) ([]byte, error) {
	headerSize := nonceSize + tagSize
	if len(data) < headerSize {
		return nil, fmt.Errorf("encrypted file is too short to contain a valid AES-GCM header")
	}
	nonce := data[:nonceSize]
	tag := data[nonceSize:headerSize]
	ciphertext := data[headerSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := make([]byte, 0, len(ciphertext)+tagSize)
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	return gcm.Open(nil, nonce, combined, nil)
}

// ---------------------------------------------------------------------------
// Run decrypted bytes
// ---------------------------------------------------------------------------

func runPlain(plain []byte, args []string) error {
	h := 64
	if len(plain) < h {
		h = len(plain)
	}
	head := strings.TrimSpace(string(plain[:h]))
	isPython := strings.HasPrefix(head, "#!") ||
		strings.HasPrefix(head, "import ") ||
		strings.HasPrefix(head, "from ") ||
		strings.HasPrefix(head, "def ")

	var tmp *os.File
	var err error
	if isPython {
		tmp, err = os.CreateTemp("", "evan-*.py")
	} else {
		tmp, err = os.CreateTemp("", "evan-*.bin")
	}
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)

	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	var c *exec.Cmd
	if isPython {
		c = exec.Command("python3", append([]string{name}, args...)...)
	} else {
		if err := os.Chmod(name, 0o700); err != nil {
			return err
		}
		if runtime.GOOS == "darwin" {
			_ = exec.Command("codesign", "--force", "--sign", "-", name).Run()
		}
		c = exec.Command(name, args...)
	}
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

func buildC(encryptedPath, keyPath string, args []string) error {
	plain, err := decryptFile(encryptedPath, keyPath)
	if err != nil {
		return err
	}
	return runPlain(plain, args)
}

// ---------------------------------------------------------------------------
// Self-contained compiler: embeds blob + key into a new Go binary
// ---------------------------------------------------------------------------

func compileSelfContained(blob, key []byte, outputName, outputDir string) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go toolchain not found in PATH: %w", err)
	}

	buildDir, err := os.MkdirTemp("", "evan-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(buildDir)

	// The encrypted payload is embedded with //go:embed.
	if err := os.WriteFile(filepath.Join(buildDir, "payload.enc"), blob, 0o644); err != nil {
		return err
	}

	src := strings.Replace(runnerTemplate, "{{KEY}}", hex.EncodeToString(key), 1)
	if err := os.WriteFile(filepath.Join(buildDir, "main.go"), []byte(src), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(buildDir, "go.mod"),
		[]byte("module evanpayload\n\ngo 1.21\n"), 0o644); err != nil {
		return err
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	outPath, err := filepath.Abs(filepath.Join(outputDir, outputName))
	if err != nil {
		return err
	}

	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", outPath, ".")
	cmd.Dir = buildDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// runnerTemplate is the generated program. {{KEY}} is replaced with the hex key.
// It embeds payload.enc, decrypts it in memory, writes to a temp file, and runs.
const runnerTemplate = `package main

import (
	_ "embed"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

//go:embed payload.enc
var payload []byte

const embeddedKeyHex = "{{KEY}}"

const (
	keySize   = 32
	nonceSize = 12
	tagSize   = 16
)

func decryptEmbedded() ([]byte, error) {
	key, err := hex.DecodeString(embeddedKeyHex)
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, fmt.Errorf("invalid key size")
	}
	data := payload
	hs := nonceSize + tagSize
	if len(data) < hs {
		return nil, fmt.Errorf("payload too short")
	}
	nonce := data[:nonceSize]
	tag := data[nonceSize:hs]
	ct := data[hs:]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(ct)+tagSize)
	buf = append(buf, ct...)
	buf = append(buf, tag...)
	return gcm.Open(nil, nonce, buf, nil)
}

func runPlain(plain []byte, args []string) error {
	h := 64
	if len(plain) < h {
		h = len(plain)
	}
	head := strings.TrimSpace(string(plain[:h]))
	isPy := strings.HasPrefix(head, "#!") ||
		strings.HasPrefix(head, "import ") ||
		strings.HasPrefix(head, "from ") ||
		strings.HasPrefix(head, "def ")
	var tmp *os.File
	var err error
	if isPy {
		tmp, err = os.CreateTemp("", "evan-*.py")
	} else {
		tmp, err = os.CreateTemp("", "evan-*.bin")
	}
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	var c *exec.Cmd
	if isPy {
		c = exec.Command("python3", append([]string{name}, args...)...)
	} else {
		if err := os.Chmod(name, 0o755); err != nil {
			return err
		}
		if runtime.GOOS == "darwin" {
			_ = exec.Command("codesign", "--force", "--sign", "-", name).Run()
		}
		c = exec.Command(name, args...)
	}
	c.Stdout, c.Stderr, c.Stdin = os.Stdout, os.Stderr, os.Stdin
	return c.Run()
}

func main() {
	plain, err := decryptEmbedded()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if err := runPlain(plain, os.Args[1:]); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
`

// ---------------------------------------------------------------------------
// Custom flag type: non-negative float
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

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
		if err := buildC(pos[0], pos[1], pos[2:]); err != nil {
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
		blob, key, err := encryptFile(target, encPath)
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
		if err := compileSelfContained(blob, key, binName, "."); err != nil {
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
