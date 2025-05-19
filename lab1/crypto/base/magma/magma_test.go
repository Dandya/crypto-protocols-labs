package magma

import (
	"crypto/subtle"
	"testing"

	"gost_magma_cbc/utils"
)

func TestMagmaSbox(t *testing.T) {
	r := sbox(bh(0xfdb97531))
	e := bh(0x2a196f34)
	if r != e {
		t.Errorf("[sbox_1] res is %d, not %d", r, e)
	}

	r = sbox(e)
	e = bh(0xebd9f03a)
	if r != e {
		t.Errorf("[sbox_2] res is %d, not %d", r, e)
	}

	r = sbox(e)
	e = bh(0xb039bb3d)
	if r != e {
		t.Errorf("[sbox_3] res is %d, not %d", r, e)
	}

	r = sbox(e)
	e = bh(0x68695433)
	if r != e {
		t.Errorf("[sbox_4] res is %d, not %d", r, e)
	}
}

func TestMagmaG(t *testing.T) {
	k := bh(0x87654321)
	n := bh(0xfedcba98)
	e := bh(0xfdcbc20c)
	if g(n, k) != e {
		t.Errorf("[g_1] res is %d, not %d", g(n, k), e)
	}

	n = k
	k = e
	e = bh(0x7e791a4b)
	if g(n, k) != e {
		t.Errorf("[g_2] res is %d, not %d", g(n, k), e)
	}

	n = k
	k = e
	e = bh(0xc76549ec)
	if g(n, k) != e {
		t.Errorf("[g_3] res is %d, not %d", g(n, k), e)
	}

	n = k
	k = e
	e = bh(0x9791c849)
	if g(n, k) != e {
		t.Errorf("[g_4] res is %d, not %d", g(n, k), e)
	}
}

func TestMagma(t *testing.T) {
	magma := Magma{}

	hdata, err := utils.ConvertHexBigEndian(
		"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	if err != nil {
		t.Error(err.Error())
	}
	key := magma.NewKey()
	subtle.ConstantTimeCopy(1, key.Data(), hdata)

	b := magma.NewBlock()
	b.SetPart(0, Part(0x76543210))
	b.SetPart(1, Part(0xfedcba98))
	magma.Encrypt(key, b, b)
	e0 := Part(0xc2d8ca3d)
	e1 := Part(0x4ee901e5)
	if b.GetPart(0).(Part) != e0 || b.GetPart(1).(Part) != e1 {
		t.Errorf("[enc] res is %d %d, not %d %d", b.GetPart(0), b.GetPart(1), e0, e1)
	}

	e0 = Part(0x76543210)
	e1 = Part(0xfedcba98)
	magma.Decrypt(key, b, b)

	if b.GetPart(0).(Part) != e0 || b.GetPart(1).(Part) != e1 {
		t.Errorf("[enc] res is %d %d, not %d %d", b.GetPart(0), b.GetPart(1), e0, e1)
	}
}
