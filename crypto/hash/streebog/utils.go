package streebog

import (
	"encoding/binary"
)

func GetU64(ptr []byte) uint64 {
	return binary.LittleEndian.Uint64(ptr)
}

func PutU64(ptr []byte, a uint64) {
	binary.LittleEndian.PutUint64(ptr, a)
}

func bytesToUint64s(b []byte) []uint64 {
	size := len(b) / 8
	dst := make([]uint64, size)

	for i := 0; i < size; i++ {
		j := i * 8

		dst[i] = binary.LittleEndian.Uint64(b[j:])
	}

	return dst
}

func uint64sToBytes(w []uint64) []byte {
	size := len(w) * 8
	dst := make([]byte, size)

	for i := 0; i < len(w); i++ {
		j := i * 8

		binary.LittleEndian.PutUint64(dst[j:], w[i])
	}

	return dst
}

func lps(block *[8]uint64) {
	ch := uint64sToBytes(block[:])

	block[0] = T[0][(ch[0])] ^ T[1][(ch[8+0])] ^ T[2][(ch[16+0])] ^ T[3][(ch[24+0])] ^ T[4][(ch[32+0])] ^ T[5][(ch[40+0])] ^ T[6][(ch[48+0])] ^ T[7][(ch[56+0])]
	block[1] = T[0][(ch[1])] ^ T[1][(ch[8+1])] ^ T[2][(ch[16+1])] ^ T[3][(ch[24+1])] ^ T[4][(ch[32+1])] ^ T[5][(ch[40+1])] ^ T[6][(ch[48+1])] ^ T[7][(ch[56+1])]
	block[2] = T[0][(ch[2])] ^ T[1][(ch[8+2])] ^ T[2][(ch[16+2])] ^ T[3][(ch[24+2])] ^ T[4][(ch[32+2])] ^ T[5][(ch[40+2])] ^ T[6][(ch[48+2])] ^ T[7][(ch[56+2])]
	block[3] = T[0][(ch[3])] ^ T[1][(ch[8+3])] ^ T[2][(ch[16+3])] ^ T[3][(ch[24+3])] ^ T[4][(ch[32+3])] ^ T[5][(ch[40+3])] ^ T[6][(ch[48+3])] ^ T[7][(ch[56+3])]
	block[4] = T[0][(ch[4])] ^ T[1][(ch[8+4])] ^ T[2][(ch[16+4])] ^ T[3][(ch[24+4])] ^ T[4][(ch[32+4])] ^ T[5][(ch[40+4])] ^ T[6][(ch[48+4])] ^ T[7][(ch[56+4])]
	block[5] = T[0][(ch[5])] ^ T[1][(ch[8+5])] ^ T[2][(ch[16+5])] ^ T[3][(ch[24+5])] ^ T[4][(ch[32+5])] ^ T[5][(ch[40+5])] ^ T[6][(ch[48+5])] ^ T[7][(ch[56+5])]
	block[6] = T[0][(ch[6])] ^ T[1][(ch[8+6])] ^ T[2][(ch[16+6])] ^ T[3][(ch[24+6])] ^ T[4][(ch[32+6])] ^ T[5][(ch[40+6])] ^ T[6][(ch[48+6])] ^ T[7][(ch[56+6])]
	block[7] = T[0][(ch[7])] ^ T[1][(ch[8+7])] ^ T[2][(ch[16+7])] ^ T[3][(ch[24+7])] ^ T[4][(ch[32+7])] ^ T[5][(ch[40+7])] ^ T[6][(ch[48+7])] ^ T[7][(ch[56+7])]
}

func xor(block *[8]uint64, data [8]uint64) {
	block[0] ^= data[0]
	block[1] ^= data[1]
	block[2] ^= data[2]
	block[3] ^= data[3]
	block[4] ^= data[4]
	block[5] ^= data[5]
	block[6] ^= data[6]
	block[7] ^= data[7]
}

func encrypt(K *[8]uint64, m []byte) {
	var tmp, mm [8]uint64
	copy(tmp[:], K[:])

	ms := bytesToUint64s(m)
	copy(mm[:], ms)

	xor(K, mm)
	for i := 0; i < 12; i++ {
		lps(K)
		xor(&tmp, IterConst[i])

		lps(&tmp)
		xor(K, tmp)
	}
}

func compress(h *[8]uint64, m []byte, N uint64) {
	var hN, mm [8]uint64
	copy(hN[:], h[:])

	ms := bytesToUint64s(m)
	copy(mm[:], ms)

	hN[0] ^= N

	lps(&hN)
	encrypt(&hN, m)
	xor(h, hN)
	xor(h, mm)
}

func add(m []byte, h *[8]uint64) {
	var carry uint64 = 0
	var overflow bool = false
	var t uint64

	m64 := bytesToUint64s(m)

	var i int
	for i = 0; i < 8; i++ {
		t = h[i] + m64[i]

		if t < h[i] || t < m64[i] {
			overflow = true
		} else {
			overflow = false
		}

		h[i] = t + carry

		if overflow {
			carry = 1
		} else {
			carry = 0
		}
	}
}
