package streebog

import "hash"

func New(hash_size int) (hash.Hash, error) {
	return newContext(hash_size)
}

func New256() hash.Hash {
	h, _ := New(256)
	return h
}

func New512() hash.Hash {
	h, _ := New(512)
	return h
}

func Sum256(data []byte) (sum256 [Size256]byte) {
	h := New256()
	h.Write(data)
	sum := h.Sum(nil)

	copy(sum256[:], sum[:Size256])
	return
}

func Sum512(data []byte) (sum512 [Size512]byte) {
	h := New512()
	h.Write(data)
	sum := h.Sum(nil)

	copy(sum512[:], sum[:Size512])
	return
}
