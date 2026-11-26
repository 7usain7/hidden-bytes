package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"poly/builder"
)

func printUsage() {
	fmt.Println("Poly Program Usage:")
	fmt.Println("  --generate <output-binary>")
	fmt.Println("  --payload <text>")
}

func main() {
	generateOut := flag.String("generate", "", "output binary path")
	payloadText := flag.String("payload", "", "payload text")
	flag.Usage = printUsage
	flag.Parse()

	if *generateOut == "" || *payloadText == "" {
		printUsage()
		os.Exit(1)
	}

	outputDir := filepath.Dir(*generateOut)
	outputName := filepath.Base(*generateOut)
	if err := builder.CompileSelfContained(*payloadText, outputName, outputDir); err != nil {
		fmt.Fprintf(os.Stderr, "\033[31merror:\033[0m %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\033[32mPolymorphic binary generated successfully as \"%s\".\033[0m\n", *generateOut)
}
