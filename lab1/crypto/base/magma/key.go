package magma

import (
	"gost_magma_cbc/crypto/models"
	"unsafe"
	_ "unsafe"
)

// little endian format
type MagmaKey struct {
	parts [8]bh
	data  []byte
}

func NewMagmaKey() models.Key {
	k := &MagmaKey{}
	k.data = unsafe.Slice((*byte)(unsafe.Pointer(&k.parts[0])), 32)
	return k
}

func (k *MagmaKey) GetPart(i int) any {
	return k.parts[i]
}

func (k *MagmaKey) PartLen() int {
	return 4
}

func (k *MagmaKey) Set(i int, v byte) {
	k.data[i] = v
}

func (k *MagmaKey) Len() int {
	return keySize
}

func (k *MagmaKey) Data() []byte {
	return k.data
}

//go:linkname memclrNoHeapPointers runtime.memclrNoHeapPointers
func memclrNoHeapPointers(ptr unsafe.Pointer, n uintptr)

func (k *MagmaKey) Clear() {
	// hdr := (*reflect.SliceHeader)(unsafe.Pointer(&k.parts))
	memclrNoHeapPointers(unsafe.Pointer(&k.parts), uintptr(keySize))
}
