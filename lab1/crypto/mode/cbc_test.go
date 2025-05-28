package mode

import (
	"crypto/subtle"
	"testing"

	"gost_magma_cbc/crypto/base/magma"
	"gost_magma_cbc/crypto/manage"
)

func TestCBC(t *testing.T) {
	ivhdata, err := manage.ConvertHexBigEndian(
		"1234567890abcdef234567890abcdef134567890abcdef12")
	if err != nil {
		t.Error(err.Error())
	}

	m := &magma.Magma{}
	block := m.NewBlock()
	cbc, err := NewCBCMode(ivhdata, block.Len())
	if err != nil {
		t.Error(err.Error())
	}

	khdata, err := manage.ConvertHexBigEndian(
		"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	if err != nil {
		t.Error(err.Error())
	}
	key := m.NewKey()
	for i := 0; i < key.Len(); i++ {
		key.Set(i, khdata[i])
	}

	p := m.NewBlock()
	p.SetPart(0, magma.Part(0x3c130a59))
	p.SetPart(1, magma.Part(0x92def06b))
	s := m.NewBlock()
	s.SetPart(0, magma.Part(0xea683919))
	s.SetPart(1, magma.Part(0x96d1b05e))
	cbc.Encrypt(m, key, p, p)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbc_p1] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	p.SetPart(0, magma.Part(0xf8189d20))
	p.SetPart(1, magma.Part(0xdb54c704))
	s.SetPart(0, magma.Part(0xabb937b9))
	s.SetPart(1, magma.Part(0xaff76129))
	cbc.Encrypt(m, key, p, p)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbc_p2] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	p.SetPart(0, magma.Part(0x67a8024c))
	p.SetPart(1, magma.Part(0x4a98fb2e))
	s.SetPart(0, magma.Part(0xc4bc0019))
	s.SetPart(1, magma.Part(0x5058b4a1))
	cbc.Encrypt(m, key, p, p)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbc_p3] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	p.SetPart(0, magma.Part(0x17b57e41))
	p.SetPart(1, magma.Part(0x8912409b))
	s.SetPart(0, magma.Part(0x7cd7e667))
	s.SetPart(1, magma.Part(0x20b78b1a))
	cbc.Encrypt(m, key, p, p)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbc_p4] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	cbcd, err := NewCBCMode(ivhdata, block.Len())
	if err != nil {
		t.Error(err.Error())
	}

	s.SetPart(0, magma.Part(0xea683919))
	s.SetPart(1, magma.Part(0x96d1b05e))
	p.SetPart(0, magma.Part(0x3c130a59))
	p.SetPart(1, magma.Part(0x92def06b))
	cbcd.Decrypt(m, key, s, s)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbcd_p1] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	s.SetPart(0, magma.Part(0xabb937b9))
	s.SetPart(1, magma.Part(0xaff76129))
	p.SetPart(0, magma.Part(0xf8189d20))
	p.SetPart(1, magma.Part(0xdb54c704))
	cbcd.Decrypt(m, key, s, s)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbcd_p2] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	s.SetPart(0, magma.Part(0xc4bc0019))
	s.SetPart(1, magma.Part(0x5058b4a1))
	p.SetPart(0, magma.Part(0x67a8024c))
	p.SetPart(1, magma.Part(0x4a98fb2e))
	cbcd.Decrypt(m, key, s, s)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbcd_p3] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}

	s.SetPart(0, magma.Part(0x7cd7e667))
	s.SetPart(1, magma.Part(0x20b78b1a))
	p.SetPart(0, magma.Part(0x17b57e41))
	p.SetPart(1, magma.Part(0x8912409b))
	cbcd.Decrypt(m, key, s, s)
	if subtle.ConstantTimeCompare(p.Data(), s.Data()) != 1 {
		t.Errorf("[cbcd_p4] not equal: %d %d, %d %d", p.GetPart(0), p.GetPart(1),
			s.GetPart(0), s.GetPart(1))
	}
}
