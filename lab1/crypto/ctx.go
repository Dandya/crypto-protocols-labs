package crypto

import (
	"crypto/subtle"
	"errors"
	"gost_magma_cbc/crypto/adder"
	"gost_magma_cbc/crypto/base/magma"
	"gost_magma_cbc/crypto/manage"
	"gost_magma_cbc/crypto/mode"
	"gost_magma_cbc/crypto/models"
	"gost_magma_cbc/utils"
	"unsafe"
)

type CryptoBase int
type CryptoMode int
type AdderType int

const (
	BaseAlgorithmMagma CryptoBase = 0
)

const (
	ModeCBC CryptoMode = 0
)

const (
	AdderType2 AdderType = 0
)

type CryptoManager struct {
	log     *utils.Log
	keysMgr manage.KeysManager
}

type CryptoCtx struct {
	Log   *utils.Log
	base  models.BaseAlgorithm
	mode  models.CryptoModeStream
	adder models.BlockAdder
	block models.Block
	Key   models.Key
	IV    []byte
}

type CryptoSettings struct {
	KeySetting struct {
		Data     manage.BuildData
		Method   manage.BuildMethod
		TimeLife int64
	}
	IVSetting struct {
		Data   manage.BuildData
		Method manage.BuildMethod
		Len    int
	}
	Base    CryptoBase
	Mode    CryptoMode
	AddType AdderType
}

func NewCryptoManager(settings *CryptoSettings, log *utils.Log) *CryptoManager {
	if log == nil || settings == nil {
		return nil
	}
	mng := &CryptoManager{}
	mng.log = log
	mng.keysMgr = *manage.NewKeysManager(settings.KeySetting.TimeLife)
	return mng
}

func (mng *CryptoManager) NewCryptoCtx(settings *CryptoSettings) *CryptoCtx {
	if settings == nil {
		return nil
	}
	ctx := &CryptoCtx{}

	ctx.Log = mng.log

	switch settings.Base {
	case BaseAlgorithmMagma:
		ctx.base = magma.NewMagma()
	default:
		mng.log.Error("[crypto] unknown base algorithm")
	}

	ctx.block = ctx.base.NewBlock()

	k, err := mng.keysMgr.GetNextKey(ctx.base, &settings.KeySetting.Data, settings.KeySetting.Method)
	if err != nil {
		mng.log.Error("[crypto][key create] " + err.Error())
		return nil
	}
	ctx.Key = k

	switch settings.Mode {
	case ModeCBC:
		iv, err := manage.BuildInitVector(&settings.IVSetting.Data, settings.IVSetting.Method, settings.IVSetting.Len)
		if err != nil {
			mng.log.Error("[crypto][cbc.iv] " + err.Error())
			return nil
		}
		ctx.IV = iv
		ctx.mode, err = mode.NewCBCMode(iv, ctx.base.BlockLen())
		if err != nil {
			mng.log.Error("[crypto][cbc.init] " + err.Error())
			return nil
		}
	default:
		mng.log.Error("[crypto] unknown crypto mode")
	}

	switch settings.AddType {
	case AdderType2:
		ctx.adder = adder.NewBlockAdder2()
	default:
		mng.log.Error("[crypto] unknown adder type")
	}

	return ctx
}

func (mng *CryptoManager) FreeCryptoCtx(ctx *CryptoCtx) {
	mng.keysMgr.Clear(ctx.Key)
}

func (ctx *CryptoCtx) Encrypt(src []byte, trg []byte) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}

	if len(src) != len(trg) {
		return 0, errors.New("source and target must have equal size")
	}

	if unsafe.Pointer(&src[0]) != unsafe.Pointer(&trg[0]) {
		subtle.ConstantTimeCopy(1, trg, src)
	}

	block_len := ctx.base.BlockLen()
	data_len := len(src)
	count := data_len / block_len
	for i := 0; i < count; i++ {
		data_b := unsafe.Slice(&trg[i*block_len], block_len)
		subtle.ConstantTimeCopy(1, ctx.block.Data(), data_b)
		ctx.mode.Encrypt(ctx.base, ctx.Key, ctx.block, ctx.block)
		subtle.ConstantTimeCopy(1, data_b, ctx.block.Data())
	}

	return count * block_len, nil
}

func (ctx *CryptoCtx) EncryptLast(src []byte, trg *[]byte) (int, error) {
	block_len := ctx.base.BlockLen()
	data_len := len(src)
	count := data_len / block_len

	n, err := ctx.Encrypt(src[:count*block_len], (*trg)[:count*block_len])
	if err != nil || n != count*block_len {
		return n, err
	}

	remains := data_len - n
	(*trg) = append((*trg), ctx.adder.GetDataFor(remains, ctx.block.Len())...)
	ln, err := ctx.Encrypt((*trg)[n:], (*trg)[n:])
	if err != nil || ln != block_len {
		return ln + n, err
	}
	return len((*trg)), nil
}

func (ctx *CryptoCtx) Decrypt(src []byte, trg []byte) (int, error) {
	if len(src) == 0 {
		return 0, nil
	}

	if len(src) != len(trg) {
		return 0, errors.New("source and target must have equal size")
	}

	if unsafe.Pointer(&src[0]) != unsafe.Pointer(&trg[0]) {
		subtle.ConstantTimeCopy(1, trg, src)
	}

	block_len := ctx.base.BlockLen()
	data_len := len(src)
	count := data_len / block_len
	for i := 0; i < count; i++ {
		data_b := unsafe.Slice(&trg[i*block_len], block_len)
		subtle.ConstantTimeCopy(1, ctx.block.Data(), data_b)
		ctx.mode.Decrypt(ctx.base, ctx.Key, ctx.block, ctx.block)
		subtle.ConstantTimeCopy(1, data_b, ctx.block.Data())
	}

	return count * block_len, nil
}

func (ctx *CryptoCtx) DecryptLast(src []byte, trg *[]byte) (int, error) {
	block_len := ctx.base.BlockLen()
	data_len := len(src)
	count := data_len / block_len

	n, err := ctx.Decrypt(src[:count*block_len], (*trg)[:count*block_len])
	if err != nil || n != count*block_len {
		return n, err
	}

	size, err := ctx.adder.GetSizeIn((*trg))
	if err != nil {
		return n, err
	}
	(*trg) = (*trg)[:size]

	return len(*trg), nil
}

func (ctx *CryptoCtx) DataAlignment() int {
	return ctx.block.Len()
}

// ! не забыть про
// ! [ ] функции шифрования
// ! [ ] освобождение контекста
// ! [ ] дополнение блока
