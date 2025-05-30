package hdrbg

import (
	"crypto/subtle"
	"errors"
	"gost_magma_cbc/crypto/models"
	"time"
)

const MAX_REQUESTS_COUNT = 1 << 48
const MAX_REQUEST_SIZE = 1 << 16
const MAX_ADDITION_LEN = 1 << 32
const SEED_SIZE = 55
const MAX_SEED_SIZE = 111
const PREFIX = "crypto:drbg:hdrbg: "

type HashDrbg struct {
	v                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedIntervalInTime    time.Duration
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	gm                      bool
	c                       []byte
	hashSize                int
	newHash                 func() models.Hasher
}

func NewHashDrbg(newHash func() models.Hasher, gm bool, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	hd := &HashDrbg{}

	hd.gm = gm
	hd.newHash = newHash

	h := newHash()
	hd.hashSize = h.Size()

	if (len(entropy) == 0 || len(entropy) >= MAX_ADDITION_LEN) {
		return nil, errors.New(PREFIX+"invalid entropy length")
	}

	if len(nonce) == 0 || len(nonce) >= MAX_ADDITION_LEN {
		return nil, errors.New(PREFIX+"invalid nonce length")
	}

	if len(personalization) >= MAX_ADDITION_LEN {
		return nil, errors.New(PREFIX+"personalization is too long")
	}

	if hd.hashSize == 64 {
		hd.v = make([]byte, SEED_SIZE)
		hd.c = make([]byte, SEED_SIZE)
		hd.seedLength = SEED_SIZE
	} else { // Поддержка 512 бит на будущее
		hd.v = make([]byte, MAX_SEED_SIZE)
		hd.c = make([]byte, MAX_SEED_SIZE)
		hd.seedLength = MAX_SEED_SIZE
	}

	// seed_material = entropy_input || instantiation_nonce || personalization_string (10.1.1.2)
	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	subtle.ConstantTimeCopy(1, seedMaterial[:len(entropy)], entropy)
	subtle.ConstantTimeCopy(1, seedMaterial[len(entropy):len(entropy)+len(nonce)], nonce)
	subtle.ConstantTimeCopy(1, seedMaterial[len(entropy)+len(nonce):len(entropy)+len(nonce)+len(personalization)], personalization)

	// seed = Hash_df(seed_material, seed_length) (10.3.1, 10.1.1.2)
	seed := hd.df(seedMaterial, hd.seedLength)
	// V = seed (10.1.1.2)
	subtle.ConstantTimeCopy(1, hd.v, seed)

	// C = Hash_df(0x00 || V, seed_length)  (10.3.1, 10.1.1.2)
	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	subtle.ConstantTimeCopy(1, temp[1:], seed)
	seed = hd.df(temp, hd.seedLength)
	subtle.ConstantTimeCopy(1, hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()

	return hd, nil
}

func (hd *HashDrbg) Reseed(entropy, additional []byte) error {
	if len(entropy) == 0 || len(entropy) >= MAX_ADDITION_LEN {
		return errors.New(PREFIX+"invalid entropy length")
	}

	if len(additional) >= MAX_ADDITION_LEN {
		return errors.New(PREFIX+"additional input too long")
	}

	seedMaterial := make([]byte, len(entropy)+hd.seedLength+len(additional)+1)
	seedMaterial[0] = 1
	subtle.ConstantTimeCopy(1, seedMaterial[1:hd.seedLength+1], hd.v)
	subtle.ConstantTimeCopy(1, seedMaterial[hd.seedLength+1:len(entropy)+hd.seedLength+1], entropy)
	subtle.ConstantTimeCopy(1, seedMaterial[len(entropy)+hd.seedLength+1:len(entropy)+hd.seedLength+len(additional)+1], additional)

	// seed = Hash_df(seed_material, seed_length) (10.3.1, 10.1.1.2)
	seed := hd.df(seedMaterial, hd.seedLength)
	// V = seed
	subtle.ConstantTimeCopy(1, hd.v, seed)

	// C = Hash_df(0x00 || V, seed_length)  (10.3.1, 10.1.1.2)
	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	subtle.ConstantTimeCopy(1, temp[1:], seed)
	seed = hd.df(temp, hd.seedLength)
	subtle.ConstantTimeCopy(1, hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *HashDrbg) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return errors.New(PREFIX+"need reseed")
	}
	if len(b) > MAX_REQUEST_SIZE {
		return errors.New(PREFIX+"too many bytes requested")
	}
	md := hd.newHash()
	m := len(b)

	// if len(additional_input) > 0, then
	// w = Hash(0x02 || V || additional_input)
	if len(additional) > 0 {
		md.Write([]byte{0x02})
		md.Write(hd.v)
		md.Write(additional)
		w := md.Sum(nil)
		md.Reset()
		hd.addW(w)
	}
	if hd.gm { // leftmost(Hash(V))
		md.Write(hd.v)
		copy(b, md.Sum(nil))
		md.Reset()
	} else {
		limit := uint64(m+md.Size()-1) / uint64(md.Size())
		data := make([]byte, hd.seedLength)
		copy(data, hd.v)
		for i := range int(limit) {
			md.Write(data)
			copy(b[i*md.Size():], md.Sum(nil))
			addOne(data, hd.seedLength)
			md.Reset()
		}
	}
	// V = (V + H + C + reseed_counter) mode 2^seed_length
	hd.addH()
	hd.addC()
	hd.addReseedCounter()

	hd.reseedCounter++
	return nil
}

func (hd *HashDrbg) NeedReseed() bool {
	return (hd.reseedCounter > hd.reseedIntervalInCounter) ||
		(hd.gm && time.Since(hd.reseedTime) > hd.reseedIntervalInTime)
}

func (hd *HashDrbg) MaxBytesPerRequest() int {
	return MAX_REQUEST_SIZE
}

func (hd *HashDrbg) df(seedMaterial []byte, len int) []byte {
	md := hd.newHash()
	limit := uint64(len+hd.hashSize-1) / uint64(hd.hashSize)
	var requireBytes [4]byte
	SetUint32(requireBytes[:], uint32(len<<3))
	var ct byte = 1
	k := make([]byte, len)
	for i := 0; i < int(limit); i++ {
		// Hash(counter_byte || return_bits || seed_material) (10.3.1)
		md.Write([]byte{ct})
		md.Write(requireBytes[:])
		md.Write(seedMaterial)
		copy(k[i*md.Size():], md.Sum(nil))
		ct++
		md.Reset()
	}
	return k
}

func (hd *HashDrbg) addW(w []byte) {
	t := make([]byte, hd.seedLength)
	subtle.ConstantTimeCopy(1, t[hd.seedLength-len(w):], w)
	add(t, hd.v, hd.seedLength)
}

func (hd *HashDrbg) addC() {
	add(hd.c, hd.v, hd.seedLength)
}

func (hd *HashDrbg) addH() {
	md := hd.newHash()
	md.Write([]byte{0x03})
	md.Write(hd.v)
	hd.addW(md.Sum(nil))
}

func (hd *HashDrbg) addReseedCounter() {
	t := make([]byte, hd.seedLength)
	SetUint64(t[hd.seedLength-8:], hd.reseedCounter)
	add(t, hd.v, hd.seedLength)
}

func add(src, dst []byte, len int) {
	var temp uint16 = 0
	for i := len - 1; i >= 0; i-- {
		temp += uint16(src[i]) + uint16(dst[i])
		dst[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

func addOne(data []byte, len int) {
	var temp uint16 = 1
	for i := len - 1; i >= 0; i-- {
		temp += uint16(data[i])
		data[i] = byte(temp & 0xff)
		temp >>= 8
	}
}

func SetUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func SetUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}