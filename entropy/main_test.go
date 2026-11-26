package main

import (
	"bytes"
	"math"
	"testing"
)

func TestCalculateReaderEntropy(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    float64
		epsilon float64
	}{
		{
			name:    "empty",
			input:   []byte{},
			want:    0.0,
			epsilon: 1e-9,
		},
		{
			name:    "uniform single byte",
			input:   bytes.Repeat([]byte{0x41}, 1024),
			want:    0.0,
			epsilon: 1e-9,
		},
		{
			name:    "equal two bytes",
			input:   bytes.Repeat([]byte{0x00, 0xFF}, 512),
			want:    1.0,
			epsilon: 1e-9,
		},
		{
			name: "all 256 byte values equally",
			input: func() []byte {
				b := make([]byte, 256)
				for i := range b {
					b[i] = byte(i)
				}
				return b
			}(),
			want:    8.0,
			epsilon: 1e-9,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, size, err := calculateReaderEntropy(bytes.NewReader(tc.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if size != int64(len(tc.input)) {
				t.Fatalf("size = %d, want %d", size, len(tc.input))
			}
			if math.Abs(got-tc.want) > tc.epsilon {
				t.Fatalf("entropy = %f, want %f", got, tc.want)
			}
		})
	}
}
