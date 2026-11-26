package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

// EncryptFile writes the encrypted blob (nonce || tag || ciphertext) + .key file
// and returns the blob plus the raw key.
func EncryptFile(targetPath, outputPath string) ([]byte, []byte, error) {
	plaintext, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, nil, err
	}

	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, NonceSize)
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

	sealed := gcm.Seal(nil, nonce, plaintext, nil) // ciphertext || tag
	ct := sealed[:len(sealed)-TagSize]
	tag := sealed[len(sealed)-TagSize:]

	blob := make([]byte, 0, NonceSize+TagSize+len(ct))
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

// DecryptFile reads the .enc and .key files from disk and decrypts the payload.
func DecryptFile(encryptedPath, keyPath string) ([]byte, error) {
	keyHex, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(keyHex)))
	if err != nil {
		return nil, err
	}
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: expected %d bytes, got %d", KeySize, len(key))
	}

	data, err := os.ReadFile(encryptedPath)
	if err != nil {
		return nil, err
	}
	return DecryptBlob(data, key)
}

// DecryptBlob decrypts an in-memory nonce || tag || ciphertext blob.
func DecryptBlob(data, key []byte) ([]byte, error) {
	headerSize := NonceSize + TagSize
	if len(data) < headerSize {
		return nil, fmt.Errorf("encrypted file is too short to contain a valid AES-GCM header")
	}
	nonce := data[:NonceSize]
	tag := data[NonceSize:headerSize]
	ciphertext := data[headerSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	combined := make([]byte, 0, len(ciphertext)+TagSize)
	combined = append(combined, ciphertext...)
	combined = append(combined, tag...)
	return gcm.Open(nil, nonce, combined, nil)
}
