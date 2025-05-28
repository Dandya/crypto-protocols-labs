package magma

import (
	"testing"
)

func TestMagmaBlock(t *testing.T) {
	magma := Magma{}

	b := magma.NewBlock()

	if b.Len() != 8 {
		t.Errorf("[len] len must be 8, now is %d", b.Len())
	}

	for i := 0; i < 8; i++ {
		b.Set(i, byte(i))
		if b.Get(i) != byte(i) {
			t.Errorf("[set] byte %d not set", i)
		}
	}
	if b.GetPart(0).(Part) != 0x03020100 || b.GetPart(1).(Part) != 0x07060504 {
		t.Errorf("[set] parts is %d %d", b.GetPart(0).(Part), b.GetPart(1).(Part))
	}

	if b.PartLen() != 4 {
		t.Errorf("[len_part] part len must be 4, now is %d", b.PartLen())
	}

	b.SetPart(0, Part(0x03020100))
	b.SetPart(1, Part(0x07060504))
	for i := 0; i < 8; i++ {
		if b.Get(i) != byte(i) {
			t.Errorf("[set_part] byte %d not set", i)
		}
	}
}
