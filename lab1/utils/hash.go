package utils

import (
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"os"
)

func CheckFile(h_t []byte, path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}

	h := hash.Sum(nil)

	return subtle.ConstantTimeCompare(h, h_t) == 1, nil
}
