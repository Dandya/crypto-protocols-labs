package hdrbg

import (
	"errors"
	"hash"
	"time"
)

const HASH_DRBG_SEED_SIZE = 55
const HASH_DRBG_MAX_SEED_SIZE = 111

type HashDrbg struct {
	v                       []byte
	c                       []byte
	seedLength              int
	reseedTime              time.Time
	reseedCounter           uint64
	reseedIntervalInCounter uint64
	securityLevel           SecurityLevel
	newHash                 func() hash.Hash
	hashSize                int
}

func NewHashDrbg(newHash func() hash.Hash, securityLevel SecurityLevel, entropy, nonce, personalization []byte) (*HashDrbg, error) {
	hd := &HashDrbg{}

	hd.newHash = newHash
	hd.setSecurityLevel(securityLevel)

	md := newHash()
	hd.hashSize = md.Size()

	if len(entropy) == 0 || len(entropy) >= MAX_BYTES {
		return nil, errors.New(PREFIX + "invalid entropy length")
	}

	if len(nonce) == 0 || len(nonce) >= MAX_BYTES>>1 {
		return nil, errors.New(PREFIX + "invalid nonce length")
	}

	if len(personalization) >= MAX_BYTES {
		return nil, errors.New(PREFIX + "personalization is too long")
	}

	if hd.hashSize <= 32 {
		hd.v = make([]byte, HASH_DRBG_SEED_SIZE)
		hd.c = make([]byte, HASH_DRBG_SEED_SIZE)
		hd.seedLength = HASH_DRBG_SEED_SIZE
	} else {
		hd.v = make([]byte, HASH_DRBG_MAX_SEED_SIZE)
		hd.c = make([]byte, HASH_DRBG_MAX_SEED_SIZE)
		hd.seedLength = HASH_DRBG_MAX_SEED_SIZE
	}
	// seed_material = entropy_input || instantiation_nonce || personalization_string
	seedMaterial := make([]byte, len(entropy)+len(nonce)+len(personalization))
	copy(seedMaterial, entropy)
	copy(seedMaterial[len(entropy):], nonce)
	copy(seedMaterial[len(entropy)+len(nonce):], personalization)

	// seed = Hash_df(seed_material, seed_length)
	seed := hd.hashDf(seedMaterial, hd.seedLength)
	// V = seed
	copy(hd.v, seed)

	// C = Hash_df(0x00 || V, seed_length)
	temp := make([]byte, hd.seedLength+1)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.hashDf(temp, hd.seedLength)
	copy(hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()

	return hd, nil
}

func (hd *HashDrbg) NeedReseed() bool {
	return (hd.reseedCounter > hd.reseedIntervalInCounter)
}

func (hd *HashDrbg) MaxBytesPerRequest() int {
	return MAX_BYTES_PER_GENERATE
}

func (hd *HashDrbg) setSecurityLevel(securityLevel SecurityLevel) {
	hd.securityLevel = securityLevel
	switch securityLevel {
	case SECURITY_LEVEL_TWO:
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL2
	case SECURITY_LEVEL_TEST:
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL_TEST
	default:
		hd.reseedIntervalInCounter = DRBG_RESEED_COUNTER_INTERVAL_LEVEL1
	}
}

// Инициализация с новой энтропией
func (hd *HashDrbg) Reseed(entropy, additional []byte) error {
	// here for the min length, we just check <=0 now
	if len(entropy) == 0 || len(entropy) >= MAX_BYTES {
		return errors.New(PREFIX + "invalid entropy length")
	}

	if len(additional) >= MAX_BYTES {
		return errors.New(PREFIX + "additional input too long")
	}
	seedMaterial := make([]byte, len(entropy)+hd.seedLength+len(additional)+1)
	seedMaterial[0] = 1
	// seed_material = 0x01 || V || entropy_input || additional_input
	copy(seedMaterial[1:], hd.v)
	copy(seedMaterial[hd.seedLength+1:], entropy)
	copy(seedMaterial[len(entropy)+hd.seedLength+1:], additional)

	// seed = Hash_df(seed_material, seed_length)
	seed := hd.hashDf(seedMaterial, hd.seedLength)

	// V = seed
	copy(hd.v, seed)
	temp := make([]byte, hd.seedLength+1)

	// C = Hash_df(0x01 || V, seed_length)
	temp[0] = 0
	copy(temp[1:], seed)
	seed = hd.hashDf(temp, hd.seedLength)
	copy(hd.c, seed)

	hd.reseedCounter = 1
	hd.reseedTime = time.Now()
	return nil
}

func (hd *HashDrbg) addW(w []byte) {
	t := make([]byte, hd.seedLength)
	copy(t[hd.seedLength-len(w):], w)
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
	setUint64(t[hd.seedLength-8:], hd.reseedCounter)
	add(t, hd.v, hd.seedLength)
}

func add(left, right []byte, len int) {
	var temp uint16 = 0
	for i := len - 1; i >= 0; i-- {
		temp += uint16(left[i]) + uint16(right[i])
		right[i] = byte(temp & 0xff)
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

func (hd *HashDrbg) Generate(b, additional []byte) error {
	if hd.NeedReseed() {
		return ErrReseedRequired
	}
	if len(b) > MAX_BYTES_PER_GENERATE {
		return errors.New(PREFIX + "too many bytes requested")
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

	// Hashgen Process
	limit := uint64(m+md.Size()-1) / uint64(md.Size())
	data := make([]byte, hd.seedLength)
	copy(data, hd.v)
	for i := range int(limit) {
		md.Write(data)
		copy(b[i*md.Size():], md.Sum(nil))
		addOne(data, hd.seedLength)
		md.Reset()
	}

	// V = (V + H + C + reseed_counter) mode 2^seed_length
	hd.addH()
	hd.addC()
	hd.addReseedCounter()

	hd.reseedCounter++
	return nil
}

// Hash_df
func (hd *HashDrbg) hashDf(seedMaterial []byte, len int) []byte {
	md := hd.newHash()
	limit := uint64(len+hd.hashSize-1) / uint64(hd.hashSize)
	var requireBytes [4]byte
	setUint32(requireBytes[:], uint32(len<<3))
	var ct byte = 1
	k := make([]byte, len)
	for i := range int(limit) {
		// Hash( counter_byte || return_bits || seed_material )
		md.Write([]byte{ct})
		md.Write(requireBytes[:])
		md.Write(seedMaterial)
		copy(k[i*md.Size():], md.Sum(nil))
		ct++
		md.Reset()
	}
	return k
}

func setUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func setUint64(b []byte, v uint64) {
	b[0] = byte(v >> 56)
	b[1] = byte(v >> 48)
	b[2] = byte(v >> 40)
	b[3] = byte(v >> 32)
	b[4] = byte(v >> 24)
	b[5] = byte(v >> 16)
	b[6] = byte(v >> 8)
	b[7] = byte(v)
}
