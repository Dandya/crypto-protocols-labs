package streebog

import (
	"errors"
)

const (
	Size256   = 32
	Size512   = 64
	BlockSize = 64
)

type context struct {
	hash   [8]uint64
	m      [BlockSize]byte
	mLen   int
	msgLen uint64

	S        [8]uint64
	hashSize int
}

func newContext(hash_size int) (*context, error) {
	switch hash_size {
	case 256, 512:
		break
	default:
		return nil, errors.New("hash/streebog: incorrect hash size")
	}

	c := &context{}
	c.hashSize = hash_size
	c.Reset()

	return c, nil
}

func (c *context) Reset() {
	c.mLen = 0
	c.msgLen = 0

	c.m = [BlockSize]byte{}

	c.hash = [8]uint64{}

	if c.hashSize == 512 {
		c.hash = initIv512
	} else {
		c.hash = initIv256
	}

	c.S = [8]uint64{}
}

func (c *context) Size() int {
	return c.hashSize / 8
}

func (c *context) BlockSize() int {
	return BlockSize
}

func (c *context) Write(p []byte) (nn int, err error) {
	nn = len(p)
	plen := len(p)
	limit := BlockSize
	for c.mLen+plen >= limit {
		offset := limit - c.mLen

		copy(c.m[c.mLen:], p)

		c.transform(false)

		plen -= offset
		c.msgLen += 512

		p = p[offset:]
		c.mLen = 0
	}

	copy(c.m[c.mLen:], p)
	c.mLen += plen

	return
}

func (c *context) Sum(in []byte) []byte {
	c0 := *c
	hash := c0.checkSum()
	return append(in, hash...)
}

func (c *context) checkSum() []byte {
	c.m[c.mLen] = 0x01
	c.mLen++

	zeros := [BlockSize]byte{}

	copy(c.m[c.mLen:], zeros[:])
	c.transform(false)
	c.msgLen += uint64(c.mLen-1) * 8

	copy(c.m[:], zeros[:])
	PutU64(c.m[:], c.msgLen)
	c.transform(true)

	SS := uint64sToBytes(c.S[:])
	copy(c.m[:], SS)
	c.transform(true)

	ss := uint64sToBytes(c.hash[8-c.hashSize/BlockSize:])
	return ss[:c.hashSize/8]
}

func (c *context) transform(last bool) {
	if last {
		compress(&c.hash, c.m[:], 0)
	} else {
		compress(&c.hash, c.m[:], c.msgLen)
	}

	if !last {
		add(c.m[:], &c.S)
	}
}
