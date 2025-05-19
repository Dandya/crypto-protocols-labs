package manage

import (
	"testing"
	"time"

	"gost_magma_cbc/crypto/base/magma"
)

func TestKeyLife(t *testing.T) {
	km := NewKeysManager(0)
	bm := magma.NewMagma()
	bd := BuildData{}
	k1, err := km.GetNextKey(bm, &bd, BuildFromRandom)
	if err != nil {
		t.Error(err)
	}
	k2, err := km.GetNextKey(bm, &bd, BuildFromRandom)
	if err != nil {
		t.Error(err)
	}

	if km.KeysCount() != 2 {
		t.Errorf("count of keys is %d, not 2", km.KeysCount())
	}
	if k1.GetPart(0) == 0 && k1.GetPart(1) == 0 {
		t.Error("key 1 is zero array")
	}
	if k2.GetPart(0) == 0 && k2.GetPart(1) == 0 {
		t.Error("key 2 is zero array")
	}

	err = km.Clear(k1)
	if err != nil {
		t.Error(err)
	}
	if km.KeysCount() != 1 {
		t.Errorf("count of keys is %d, not 1", km.KeysCount())
	}

	err = km.Clear(k2)
	if err != nil {
		t.Error(err)
	}
	if km.KeysCount() != 0 {
		t.Errorf("count of keys is %d, not 0", km.KeysCount())
	}
}

func TestTimeLife(t *testing.T) {
	km := NewKeysManager(1)
	bm := magma.NewMagma()
	bd := BuildData{}
	k, err := km.GetNextKey(bm, &bd, BuildFromRandom)
	if err != nil {
		t.Error(err)
	}

	r, err := km.IsAvailable(k)
	if err != nil {
		t.Error(err)
	}
	if !r {
		t.Error("key is not available")
	}
	time.Sleep(2 * time.Second)
	r, err = km.IsAvailable(k)
	if err != nil {
		t.Error(err)
	}
	if r {
		t.Error("key is available")
	}
}
