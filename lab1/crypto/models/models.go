package models

type Key interface {
	GetPart(i int) any
	Set(i int, v byte)
	PartLen() int
	Len() int
	Data() []byte
	Clear()
}

type Block interface {
	GetPart(i int) any
	SetPart(i int, v any)
	Get(i int) byte
	Set(i int, v byte)
	PartLen() int
	Len() int
	Data() []byte
	Clear()
}

type Mode int

const (
	EncryptMode Mode = 0
	DecryptMode Mode = 1
)

type BaseAlgorithm interface {
	Encrypt(key Key, src, dst Block)
	Decrypt(key Key, src, dst Block)
	NewKey() Key
	NewBlock() Block
	BlockLen() int
	KeyLen() int
}

type BlockAdder interface {
	GetDataFor(remains_len int, block_len int) []byte
	GetSizeIn(data []byte) (int, error)
}

type CryptoModeStream interface {
	Encrypt(base BaseAlgorithm, key Key, src Block, dst Block)
	Decrypt(base BaseAlgorithm, key Key, src Block, dst Block)
}
