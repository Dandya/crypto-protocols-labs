package adder

import (
	"errors"
	"gost_magma_cbc/crypto/models"
)

type BlockAdder2 struct {
}

func NewBlockAdder2() models.BlockAdder {
	return &BlockAdder2{}
}

func (a *BlockAdder2) GetDataFor(remains_len int, block_len int) []byte {
	res := make([]byte, 0, block_len)
	zero_count := 0
	if remains_len == 0 {
		zero_count = block_len - 1
	} else {
		zero_count = block_len - remains_len - 1
	}
	res = append(res, 0x80)
	for i := 0; i < zero_count; i++ {
		res = append(res, 0)
	}
	return res
}

func (a *BlockAdder2) GetSizeIn(data []byte) (int, error) {
	size := len(data) - 1
	for {
		if data[size] == 0x00 {
			size--
			continue
		}
		if data[size] != 0x80 {
			return 0, errors.New("unsupported block")
		}
		return size, nil
	}
}
