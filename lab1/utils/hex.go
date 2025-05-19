package utils

import (
	"encoding/hex"
)

func ConvertHexBigEndian(h string) ([]byte, error) {
	hdata, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	// to little endian
	for i, j := 0, len(hdata)-1; i < j; i, j = i+1, j-1 {
		hdata[i], hdata[j] = hdata[j], hdata[i]
	}
	return hdata, nil
}

func ConvertHexLittleEndian(h string) ([]byte, error) {
	return hex.DecodeString(h)
}
