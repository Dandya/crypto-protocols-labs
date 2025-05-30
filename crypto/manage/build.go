package manage

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"gost_magma_cbc/crypto/models"
	"os"
)

type BuildMethod int

const (
	BuildFromBEString BuildMethod = 0
	BuildFromLEString BuildMethod = 1
	BuildFromBytes    BuildMethod = 2
	BuildFromFile     BuildMethod = 3
	BuildFromRandom   BuildMethod = 4
	BuildFromKDF      BuildMethod = 5
)

type BuildData struct {
	BEString *string
	LEString *string
	File     *string
	Bytes    *[]byte
	Kdf      models.KDFParams
	Prng     models.DRBGPrng
}

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

func BuildFrom(data *BuildData, method BuildMethod, l int) ([]byte, error) {
	if data == nil {
		return nil, errors.New("nil data")
	}
	switch method {
	case BuildFromBEString:
		if data.BEString == nil {
			return nil, errors.New("nil big endian string")
		}
		b, err := ConvertHexBigEndian(*data.BEString)
		if err != nil {
			return nil, err
		}
		if len(b) != l {
			fmt.Println(l)
			fmt.Println(len(b))
			return nil, errors.New("incorrect big endian string")
		}
		return b, nil
	case BuildFromLEString:
		if data.LEString == nil {
			return nil, errors.New("nil little endian string")
		}
		b, err := ConvertHexLittleEndian(*data.LEString)
		if err != nil {
			return nil, err
		}
		if len(b) != l {
			return nil, errors.New("incorrect little endian string")
		}
		return b, nil
	case BuildFromBytes:
		if data.Bytes == nil {
			return nil, errors.New("nil bytes data")
		}
		if len(*data.Bytes) != l {
			return nil, errors.New("incorrect bytes data")
		}
		return *data.Bytes, nil
	case BuildFromFile:
		if data.File == nil {
			return nil, errors.New("nil file path")
		}
		b, err := os.ReadFile(*data.File)
		if err != nil {
			return nil, err
		}
		if len(b) != l {
			return nil, errors.New("incorrect file data")
		}
		return b, nil
	case BuildFromRandom:
		b := make([]byte, l)
		var n int
		var err error
		if data.Prng != nil {
			n, err = data.Prng.Read(b)
		} else {
			n, err = rand.Read(b)
		}
		if err != nil {
			return nil, err
		}
		if n != l {
			return nil, errors.New("error reading random data")
		}
		return b, nil
	case BuildFromKDF:
		if l > data.Kdf.Kdf.MaxSize() {
			return nil, errors.New("len above supported len")
		}
		return data.Kdf.Kdf.Create(data.Kdf.Key, data.Kdf.Label, data.Kdf.Seed)
	default:
		return nil, errors.New("unknown method")
	}
}

func BuildInitVector(data *BuildData, method BuildMethod, len int) ([]byte, error) {
	return BuildFrom(data, method, len)
}

func BuildKey(data *BuildData, method BuildMethod, key models.Key) error {
	b, err := BuildFrom(data, method, key.Len())
	if err != nil {
		return err
	}
	subtle.ConstantTimeCopy(1, key.Data(), b)
	return nil
}
