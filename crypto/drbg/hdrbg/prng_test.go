package hdrbg

import (
	"crypto/sha256"
	"gost_magma_cbc/crypto/hash/streebog"
	"testing"
)

func Test_HashDrbgPrngWithSha256(t *testing.T) {
	prng, err := NewHashDrbgPrng(sha256.New, nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, MAX_BYTES_PER_GENERATE+1)
	n, err := prng.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != MAX_BYTES_PER_GENERATE+1 {
		t.Errorf("not got enough random bytes")
	}
}

func Test_HashDrbgPrngWithStreebog(t *testing.T) {
	prng, err := NewHashDrbgPrng(streebog.New256, nil, 32, SECURITY_LEVEL_TEST, nil)
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, MAX_BYTES_PER_GENERATE+1)
	n, err := prng.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != MAX_BYTES_PER_GENERATE+1 {
		t.Errorf("not got enough random bytes")
	}
}
