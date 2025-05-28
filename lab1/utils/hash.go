package utils

import (
	"crypto/subtle"
	"gost_magma_cbc/crypto/hash/streebog"
	"io"
	"os"
)

func CheckFile(ht []byte, path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	hash := streebog.New256()

	if _, err := io.Copy(hash, file); err != nil {
		return false, err
	}

	h := hash.Sum(nil)

	return subtle.ConstantTimeCompare(h, ht) == 1, nil
}
