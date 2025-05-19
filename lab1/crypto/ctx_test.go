package crypto

import (
	"crypto/subtle"
	"gost_magma_cbc/crypto/manage"
	"gost_magma_cbc/utils"
	"os"
	"testing"
)

func TestCrypto(t *testing.T) {
	log, err := utils.NewLog("")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove("")

	iv_s := "1234567890abcdef234567890abcdef134567890abcdef12"
	key_s := "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	settings := CryptoSettings{}
	settings.KeySetting.Data = manage.BuildData{BEString: &key_s}
	settings.KeySetting.Method = manage.BuildFromBEString
	settings.KeySetting.TimeLife = 0
	settings.IVSetting.Data = manage.BuildData{BEString: &iv_s}
	settings.IVSetting.Method = manage.BuildFromBEString
	settings.IVSetting.Len = 24
	settings.Base = BaseAlgorithmMagma
	settings.Mode = ModeCBC
	settings.AddType = AdderType2
	mng := NewCryptoManager(&settings, log)
	if mng == nil {
		t.Fatal("mng is nil")
	}
	ctx := mng.NewCryptoCtx(&settings)
	if ctx == nil {
		t.Fatal("ctx is nil")
	}

	data_s := "8912409b17b57e414a98fb2e67a8024cdb54c704f8189d2092def06b3c130a59"
	bd := manage.BuildData{BEString: &data_s}
	data, err := manage.BuildFrom(&bd, manage.BuildFromBEString, 32)
	if err != nil {
		t.Fatal(err)
	}

	size, err := ctx.EncryptLast(data, &data)
	if err != nil {
		t.Fatal(err)
	}
	if size != 40 || len(data) != 40 {
		t.Fatalf("[enc] size incorrect %d (%d)", size, len(data))
	}
	mng.FreeCryptoCtx(ctx)

	ctx = mng.NewCryptoCtx(&settings)
	if ctx == nil {
		t.Fatal("ctx is nil")
	}

	size, err = ctx.DecryptLast(data, &data)
	if err != nil {
		t.Fatal(err)
	}
	if size != 32 || len(data) != 32 {
		t.Fatalf("[dec] size incorrect %d (%d)", size, len(data))
	}

	data_t, err := manage.BuildFrom(&bd, manage.BuildFromBEString, 32)
	if err != nil {
		t.Fatal(err)
	}
	r := subtle.ConstantTimeCompare(data, data_t)
	if r == 0 {
		t.Errorf("decrypt error")
	}
}
