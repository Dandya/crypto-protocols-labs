package magma

import (
	"gost_magma_cbc/crypto/models"
)

type bh uint32
type Part bh
type Sbox [8][16]uint8
type IterKeysIds [32]int

var Sbox34_12_2018 = Sbox([8][16]uint8{
	{12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
	{6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
	{11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
	{12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
	{7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
	{5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
	{8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
	{1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2},
})

const (
	keySize       = 32
	blockSize     = 8
	iterKeysCount = 32
)

var (
	// little endian key
	IterKeys = []IterKeysIds{
		{ // encrypt
			7, 6, 5, 4, 3, 2, 1, 0,
			7, 6, 5, 4, 3, 2, 1, 0,
			7, 6, 5, 4, 3, 2, 1, 0,
			0, 1, 2, 3, 4, 5, 6, 7,
		},
		{ // decrypt
			7, 6, 5, 4, 3, 2, 1, 0,
			0, 1, 2, 3, 4, 5, 6, 7,
			0, 1, 2, 3, 4, 5, 6, 7,
			0, 1, 2, 3, 4, 5, 6, 7,
		},
	}
)

type Magma struct {
}

func NewMagma() models.BaseAlgorithm {
	return &Magma{}
}

func (m *Magma) NewBlock() models.Block {
	return NewMagmaBlock()
}

func (*Magma) NewKey() models.Key {
	return NewMagmaKey()
}

func (m *Magma) GetIterKey(key models.Key, i int, mode models.Mode) bh {
	return key.GetPart(IterKeys[mode][i]).(bh)
}

func sbox(n bh) bh {
	return bh(Sbox34_12_2018[0][(n>>0)&0x0F])<<0 +
		bh(Sbox34_12_2018[1][(n>>4)&0x0F])<<4 +
		bh(Sbox34_12_2018[2][(n>>8)&0x0F])<<8 +
		bh(Sbox34_12_2018[3][(n>>12)&0x0F])<<12 +
		bh(Sbox34_12_2018[4][(n>>16)&0x0F])<<16 +
		bh(Sbox34_12_2018[5][(n>>20)&0x0F])<<20 +
		bh(Sbox34_12_2018[6][(n>>24)&0x0F])<<24 +
		bh(Sbox34_12_2018[7][(n>>28)&0x0F])<<28
}

func shift11(n bh) bh {
	return (n << 11) | (n >> (32 - 11))
}

func g(n bh, k bh) bh {
	return shift11(sbox(n + k))
}

func (m *Magma) crypt(key models.Key, seq IterKeysIds, src, trg models.Block) {
	l, r := bh(src.GetPart(1).(Part)), bh(src.GetPart(0).(Part))
	for _, i := range seq {
		l, r = r, g(r, bh(key.GetPart(i).(bh)))^l
	}
	trg.SetPart(0, Part(l))
	trg.SetPart(1, Part(r))
}

func (m *Magma) Encrypt(key models.Key, src, trg models.Block) {
	m.crypt(key, IterKeys[0], src, trg)
}

func (m *Magma) Decrypt(key models.Key, src, trg models.Block) {
	m.crypt(key, IterKeys[1], src, trg)
}

func (m *Magma) BlockLen() int {
	return blockSize
}

func (m *Magma) KeyLen() int {
	return keySize
}
