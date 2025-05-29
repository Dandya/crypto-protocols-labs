package manage

import (
	"errors"
	"gost_magma_cbc/crypto/models"
	"sync"
	"time"
	"unsafe"
)

type KeyInfo struct {
	Key        models.Key
	Count      int
	CreateTime int64
}

type KeysManager struct {
	keyTimeLife int64
	usingKeys   []KeyInfo
	mtx         sync.Mutex
	log         models.Log
}

func NewKeysManager(time_life int64) *KeysManager {
	return &KeysManager{keyTimeLife: time_life}
}

func NewKeysManagerWithLog(time_life int64, log models.Log) *KeysManager {
	return &KeysManager{keyTimeLife: time_life, log: log}
}

func (km *KeysManager) IsAvailable(key models.Key) (bool, error) {
	if km.keyTimeLife == 0 {
		return false, nil
	}

	km.mtx.Lock()
	defer km.mtx.Unlock()

	for i := 0; i < len(km.usingKeys); i++ {
		if unsafe.Pointer(&km.usingKeys[i].Key.Data()[0]) ==
			unsafe.Pointer(&key.Data()[0]) {
			return km.usingKeys[i].CreateTime+km.keyTimeLife >= time.Now().Unix(), nil
		}
	}
	return false, errors.New("key not find")
}

func (km *KeysManager) isAvailable(key KeyInfo) bool {
	if km.keyTimeLife != 0 && key.Key != nil {
		return (km.keyTimeLife > time.Now().Unix()-key.CreateTime)
	}
	return false
}

// func fillKey(b []byte, k models.Key) {
// 	subtle.ConstantTimeCopy(1, k.Data(), b)
// }

func (km *KeysManager) addNewKey(b models.BaseAlgorithm, data *BuildData,
	method BuildMethod) error {
	k := b.NewKey()
	err := BuildKey(data, method, k)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	km.usingKeys = append(km.usingKeys, KeyInfo{Key: k, Count: 1, CreateTime: now})
	if km.log != nil {
		km.log.Info("crypto::KeyManager: new key created")
	}
	return nil
}

func (km *KeysManager) GetNextKey(b models.BaseAlgorithm, data *BuildData,
	method BuildMethod) (models.Key, error) {
	km.mtx.Lock()
	defer km.mtx.Unlock()

	if len(km.usingKeys) == 0 || !km.isAvailable(km.usingKeys[len(km.usingKeys)-1]) {
		err := km.addNewKey(b, data, method)
		if err != nil {
			return nil, err
		}
	}

	return km.usingKeys[len(km.usingKeys)-1].Key, nil
}

func (km *KeysManager) Clear(key models.Key) error {
	km.mtx.Lock()
	defer km.mtx.Unlock()

	for i := 0; i < len(km.usingKeys); i++ {
		if unsafe.Pointer(&km.usingKeys[i].Key.Data()[0]) ==
			unsafe.Pointer(&key.Data()[0]) {
			k := &km.usingKeys[i]
			k.Count--
			if k.Count == 0 {
				k.Key.Clear()
				km.usingKeys = append(km.usingKeys[:i], km.usingKeys[i+1:]...)
				if km.log != nil {
					km.log.Info("crypto::KeyManager: key deleted")
				}
			}
			return nil
		}
	}
	return errors.New("key not find")
}

func (km *KeysManager) KeysCount() int {
	return len(km.usingKeys)
}
