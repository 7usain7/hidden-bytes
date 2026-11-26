package main

import (
	"flag"
	"fmt"
	"io"
	"math"
	"os"
)

// shannonEntropy computes the Shannon entropy (in bits per byte, 0.0 to 8.0)
// from a 256-entry byte frequency table and total byte count.
func shannonEntropy(counts [256]uint64, total uint64) float64 {
	if total == 0 {
		return 0.0
	}
	var entropy float64
	fTotal := float64(total)
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / fTotal
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func calculateReaderEntropy(r io.Reader) (float64, int64, error) {
	var counts [256]uint64
	var total uint64
	buf := make([]byte, 32*1024)

	for {
		n, err := r.Read(buf)
		if n > 0 {
			for _, b := range buf[:n] {
				counts[b]++
			}
			total += uint64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, int64(total), err
		}
	}

	return shannonEntropy(counts, total), int64(total), nil
}

func calculateFileEntropy(path string) (float64, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	return calculateReaderEntropy(f)
}

func main() {
	filePath := flag.String("calculate", "", "File path to calculate Shannon entropy (0-8)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  %s --calculate <file>\n", os.Args[0])
	}
	flag.Parse()

	if *filePath == "" {
		flag.Usage()
		os.Exit(1)
	}

	ent, _, err := calculateFileEntropy(*filePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("%.4f\n", ent)
}
