package adder

import "testing"

func TestAdder2(t *testing.T) {
	adder := BlockAdder2{}

	r := adder.GetDataFor(4, 8)
	e := []byte{0x80, 0, 0, 0}
	if len(r) != len(e) {
		t.Errorf("[half] result is %d, not is %d", len(r), len(e))
	}
	for i := 0; i < len(e); i++ {
		if r[i] != e[i] {
			t.Errorf("[half] byte %d by %d, not is %d", r[i], i, e[i])
		}
	}

	r = adder.GetDataFor(1, 8)
	e = []byte{0x80, 0, 0, 0, 0, 0, 0}
	if len(r) != len(e) {
		t.Errorf("[one] result is %d, not is %d", len(r), len(e))
	}
	for i := 0; i < len(e); i++ {
		if r[i] != e[i] {
			t.Errorf("[one] byte %d by %d, not is %d", r[i], i, e[i])
		}
	}

	r = adder.GetDataFor(7, 8)
	e = []byte{0x80}
	if len(r) != len(e) {
		t.Errorf("[max] result is %d, not is %d", len(r), len(e))
	}
	for i := 0; i < len(e); i++ {
		if r[i] != e[i] {
			t.Errorf("[max] byte %d by %d, not is %d", r[i], i, e[i])
		}
	}

	r = adder.GetDataFor(0, 8)
	e = []byte{0x80, 0, 0, 0, 0, 0, 0, 0}
	if len(r) != len(e) {
		t.Errorf("[min] result is %d, not is %d", len(r), len(e))
	}
	for i := 0; i < len(e); i++ {
		if r[i] != e[i] {
			t.Errorf("[min] byte %d by %d, not is %d", r[i], i, e[i])
		}
	}
}
