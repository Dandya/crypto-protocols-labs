package hdrbg

import (
	"crypto/rand"
	"errors"
	"gost_magma_cbc/crypto/models"
	"hash"
	"io"
)

const DRBG_RESEED_COUNTER_INTERVAL_LEVEL_TEST uint64 = 8
const DRBG_RESEED_COUNTER_INTERVAL_LEVEL2 uint64 = 1 << 10
const DRBG_RESEED_COUNTER_INTERVAL_LEVEL1 uint64 = 1 << 20

const MAX_BYTES = 1 << 45
const MAX_BYTES_PER_GENERATE = 1 << 16

const PREFIX = "crypto:drbg:hdrbg: "

var ErrReseedRequired = errors.New(PREFIX + "reseed required")

type SecurityLevel byte

const (
	SECURITY_LEVEL_ONE  SecurityLevel = 0x01
	SECURITY_LEVEL_TWO  SecurityLevel = 0x02
	SECURITY_LEVEL_TEST SecurityLevel = 0x99
)

type DrbgPrng struct {
	entropySource    io.Reader
	securityStrength int
	drbg             models.DRBG
}

func NewHashDrbgPrng(newHash func() hash.Hash, entropySource io.Reader, securityStrength int, securityLevel SecurityLevel, personalization []byte) (*DrbgPrng, error) {
	prng := &DrbgPrng{}

	if entropySource != nil {
		prng.entropySource = entropySource
	} else {
		prng.entropySource = rand.Reader
	}
	prng.securityStrength = selectSecurityStrength(securityStrength) // в байтах
	if securityStrength < 32 {
		return nil, errors.New(PREFIX + "invalid security strength")
	}

	// Получение энтропии для инициализации данных
	entropyInput := make([]byte, prng.securityStrength)
	err := prng.getEntropy(entropyInput)
	if err != nil {
		return nil, err
	}

	// Получение метки (8.6.7)
	nonce := make([]byte, prng.securityStrength/2)
	err = prng.getEntropy(nonce)
	if err != nil {
		return nil, err
	}

	// Инициализация генератора случайных бит
	prng.drbg, err = NewHashDrbg(newHash, securityLevel, entropyInput, nonce, personalization)
	if err != nil {
		return nil, err
	}

	return prng, nil
}

func (prng *DrbgPrng) getEntropy(entropyInput []byte) error {
	n, err := prng.entropySource.Read(entropyInput)
	if err != nil {
		return err
	}
	if n != len(entropyInput) {
		return errors.New(PREFIX + "fail to read enough entropy input")
	}
	return nil
}

func (prng *DrbgPrng) Read(data []byte) (int, error) {
	maxBytesPerRequest := prng.drbg.MaxBytesPerRequest()
	total := 0

	// Заполнение массива случайными данными
	for len(data) > 0 {
		b := data
		if len(data) > maxBytesPerRequest {
			b = data[:maxBytesPerRequest]
		}

		err := prng.drbg.Generate(b, nil)
		if err == ErrReseedRequired {
			entropyInput := make([]byte, prng.securityStrength)
			err := prng.getEntropy(entropyInput)
			if err != nil {
				return 0, err
			}
			err = prng.drbg.Reseed(entropyInput, nil)
			if err != nil {
				return 0, err
			}
		} else if err != nil {
			return 0, err
		} else {
			total += len(b)
			data = data[len(b):]
		}
	}
	return total, nil
}

// Возвращает наибольшую длину порождающих данных, которая необходима для
// переданного уровня безопасности.
func selectSecurityStrength(requested int) int {
	switch {
	case requested <= 14:
		return 14
	case requested <= 16:
		return 16
	case requested <= 24:
		return 24
	case requested <= 32:
		return 32
	default:
		return requested
	}
}
