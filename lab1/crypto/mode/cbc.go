package mode

import (
	"crypto/subtle"
	"errors"
	"gost_magma_cbc/crypto/models"
	"unsafe"
)

type CBCMode struct {
	reg   []byte
	curr  int
	block []byte
}

func NewCBCMode(req []byte, block_len int) (models.CryptoModeStream, error) {
	if len(req) < block_len {
		return nil, errors.New("register size must be equal or above than block len")
	}
	block := make([]byte, block_len)
	req_c := make([]byte, len(req))
	copy(req_c, req)
	return &CBCMode{reg: req_c, curr: len(req) - block_len, block: block}, nil
}

// const result
func (m *CBCMode) msb() []byte {
	reg_len := len(m.reg)
	n := len(m.block)
	for i := 0; i < n; i++ {
		m.block[i] = m.reg[(m.curr+i)%reg_len]
	}
	return m.block
}

func (m *CBCMode) xor(b models.Block) {
	subtle.XORBytes(b.Data(), m.block, b.Data())
}

func (m *CBCMode) Encrypt(base models.BaseAlgorithm, key models.Key,
	src models.Block, dst models.Block) {
	if unsafe.Pointer(&src.Data()[0]) != unsafe.Pointer(&dst.Data()[0]) {
		subtle.ConstantTimeCopy(1, dst.Data(), src.Data())
	}
	m.msb()
	m.xor(dst)
	base.Encrypt(key, dst, dst)
	reg_len := len(m.reg)
	for i := 0; i < dst.Len(); i++ {
		m.reg[(m.curr+i)%reg_len] = dst.Data()[i]
	}
	m.curr = (m.curr - dst.Len() + reg_len) % reg_len
}

func (m *CBCMode) Decrypt(base models.BaseAlgorithm, key models.Key,
	src models.Block, dst models.Block) {
	if unsafe.Pointer(&src.Data()[0]) != unsafe.Pointer(&dst.Data()[0]) {
		subtle.ConstantTimeCopy(1, dst.Data(), src.Data())
	}
	tmp := make([]byte, dst.Len())
	subtle.ConstantTimeCopy(1, tmp, dst.Data())
	m.msb()
	base.Decrypt(key, dst, dst)
	m.xor(dst)
	reg_len := len(m.reg)
	for i := 0; i < dst.Len(); i++ {
		m.reg[(m.curr+i)%reg_len] = tmp[i]
	}
	m.curr = (m.curr - dst.Len() + reg_len) % reg_len
}
