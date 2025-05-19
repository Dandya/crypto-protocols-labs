package magma

import (
	"crypto/subtle"
	"gost_magma_cbc/crypto/models"
	"gost_magma_cbc/utils"
	"os"
	"testing"
)

func TestMagmaKey(t *testing.T) {
	magma := Magma{}

	hdata, err := utils.ConvertHexBigEndian(
		"ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")
	if err != nil {
		t.Error(err.Error())
	}
	key := magma.NewKey()
	subtle.ConstantTimeCopy(1, key.Data(), hdata)

	enc_true_data := [32]uint32{0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
		0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff, 0xffeeddcc, 0xbbaa9988,
		0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff,
		0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100, 0xf0f1f2f3, 0xf4f5f6f7,
		0xf8f9fafb, 0xfcfdfeff, 0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
		0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc}
	if err != nil {
		t.Error(err.Error())
		os.Exit(1)
	}
	for i := 0; i < 32; i++ {
		if uint32(magma.GetIterKey(key, i, models.EncryptMode)) != enc_true_data[i] {
			t.Errorf("[enc] not equal: [%d] != %d by %d", enc_true_data[i],
				uint32(magma.GetIterKey(key, i, models.EncryptMode)), i)
		}
	}

	dec_true_data := [32]uint32{0xffeeddcc, 0xbbaa9988, 0x77665544, 0x33221100,
		0xf0f1f2f3, 0xf4f5f6f7, 0xf8f9fafb, 0xfcfdfeff, 0xfcfdfeff, 0xf8f9fafb,
		0xf4f5f6f7, 0xf0f1f2f3, 0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc,
		0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3, 0x33221100, 0x77665544,
		0xbbaa9988, 0xffeeddcc, 0xfcfdfeff, 0xf8f9fafb, 0xf4f5f6f7, 0xf0f1f2f3,
		0x33221100, 0x77665544, 0xbbaa9988, 0xffeeddcc}
	if err != nil {
		t.Error(err.Error())
		os.Exit(1)
	}
	for i := 0; i < 32; i++ {
		if uint32(magma.GetIterKey(key, i, models.DecryptMode)) != dec_true_data[i] {
			t.Errorf("[dec] not equal: [%d] != %d by %d", dec_true_data[i],
				uint32(magma.GetIterKey(key, i, models.DecryptMode)), i)
		}
	}

	key.Clear()
	for i := 0; i < 32; i++ {
		if uint32(magma.GetIterKey(key, i, models.EncryptMode)) != 0 {
			t.Errorf("[clear] not equal: [%d] != %d by %d", 0,
				uint32(magma.GetIterKey(key, i, models.EncryptMode)), i)
		}
	}
}
