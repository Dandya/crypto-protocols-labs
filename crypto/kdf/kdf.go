package kdf

import (
	"crypto/subtle"
	"gost_magma_cbc/crypto/hash/hmac"
	"gost_magma_cbc/crypto/models"
)


type KDF256 struct {
	h models.HMAC
}

func NewKDF256() models.KDF {
	return &KDF256{h: hmac.NewHMAC256()}
}

func (k *KDF256) Create(key []byte, label []byte, seed []byte) ([]byte, error) {
	len_label := len(label)
	len_seed := len(seed)
	data := make([]byte, len_label + len_seed + 4);

	data[0] = 0x01
	subtle.ConstantTimeCopy(1, data[1:len_label+1], label)
	data[len_label+1] = 0x00
	subtle.ConstantTimeCopy(1, data[len_label+2:len_label+len_seed+2], seed)
	data[len_label+len_seed+2] = 0x01
	data[len_label+len_seed+3] = 0x00

	return k.h.Sum(key, data)
}