package magma

import (
	"gost_magma_cbc/crypto/models"
	"unsafe"
)

// little endian format
type MagmaBlock struct {
	parts [2]bh
	data  []byte
}

func NewMagmaBlock() models.Block {
	b := &MagmaBlock{}
	//num := uintptr(len(theBytes)) * unsafe.Sizeof(theBytes[0]) / unsafe.Sizeof(int32(0))
	b.data = unsafe.Slice((*byte)(unsafe.Pointer(&b.parts[0])), 8)
	return b
}

func (b *MagmaBlock) GetPart(i int) any {
	return Part(b.parts[i])
}

func (b *MagmaBlock) SetPart(i int, v any) {
	b.parts[i] = bh(v.(Part))
}

func (b *MagmaBlock) PartLen() int {
	return 4
}

func (b *MagmaBlock) Get(i int) byte {
	return b.data[i]
}

func (b *MagmaBlock) Set(i int, v byte) {
	b.data[i] = v
}

func (b *MagmaBlock) Len() int {
	return blockSize
}

func (b *MagmaBlock) Data() []byte {
	return b.data
}

func (b *MagmaBlock) Clear() {
	b.parts[0] = 0
	b.parts[1] = 0
}
