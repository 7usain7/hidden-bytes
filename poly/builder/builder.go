package builder

import (
	_ "embed"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

//go:embed runner.go.tmpl
var runnerTemplate string

// CompileSelfContained inserts the payload text into runner.go.tmpl and
// compiles it into a standalone Go binary.
func CompileSelfContained(payloadText, outputName, outputDir string) error {
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("go toolchain not found in PATH: %w", err)
	}

	buildDir, err := os.MkdirTemp("", "poly-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(buildDir)

	quoted := strconv.Quote(payloadText)
	escaped := quoted[1 : len(quoted)-1]
	src := strings.Replace(runnerTemplate, "{{PAYLOAD}}", escaped, 1)
	if err := os.WriteFile(filepath.Join(buildDir, "main.go"), []byte(src), 0o644); err != nil {
		return err
	}

	if err := os.WriteFile(filepath.Join(buildDir, "go.mod"),
		[]byte("module polyrunner\n\ngo 1.21\n"), 0o644); err != nil {
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
	if strings.HasSuffix(strings.ToLower(outputName), ".exe") {
		cmd.Env = append(os.Environ(), "GOOS=windows", "GOARCH=arm64")
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if cmd_err := cmd.Run(); cmd_err != nil {
		return cmd_err
	}

	f, err := os.OpenFile(outPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	utcTime := time.Now().UTC()
	_, err = f.WriteString(utcTime.Format(time.RFC3339))
	return err
}
