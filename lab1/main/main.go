package main

import (
	"crypto/subtle"
	"fmt"
	"gost_magma_cbc/crypto"
	"gost_magma_cbc/crypto/manage"
	"gost_magma_cbc/utils"
	"os"
	"strconv"
	"time"
)

func F(b []byte) {
	b[0] = '0'
}

func EncryptFile(in, out string, ctx *crypto.CryptoCtx, buff_len int) {
	buff := make([]byte, buff_len)
	fileInfo, err := os.Stat(in)
	if err != nil {
		ctx.Log.Fatal(err.Error())
	}
	file_r, err := os.OpenFile(in, os.O_RDONLY, 0666)
	if err != nil {
		ctx.Log.Fatal(err.Error())
	}
	defer file_r.Close()
	file_w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		ctx.Log.Fatal(err.Error())
	}
	defer file_w.Close()
	count := int(fileInfo.Size()) / buff_len
	if int(fileInfo.Size())%buff_len > 0 {
		count += 1
	}
	for i := 0; i < count; i++ {
		if i != count-1 {
			n, err := file_r.Read(buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != buff_len {
				ctx.Log.Fatal("[enc] error in reading from file")
			}
			n, err = ctx.Encrypt(buff, buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != buff_len {
				ctx.Log.Fatal("[enc] error in encrypting file")
			}
			n, err = file_w.Write(buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != buff_len {
				ctx.Log.Fatal("[enc] error in writing into file")
			}
		} else {
			n, err := file_r.Read(buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			last_part := buff[:n]
			ln, err := ctx.EncryptLast(last_part, &last_part)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			n, err = file_w.Write(last_part)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != ln {
				ctx.Log.Fatal("[enc_last] error in writing into file")
			}
		}
	}
}

func DecryptFile(in, out string, ctx *crypto.CryptoCtx, buff_len int) {
	buff := make([]byte, buff_len)
	fileInfo, err := os.Stat(in)
	if err != nil {
		ctx.Log.Fatal(err.Error())
	}
	file_r, err := os.OpenFile(in, os.O_RDONLY, 0666)
	if err != nil {
		ctx.Log.Fatal(err.Error())
	}
	defer file_r.Close()
	file_w, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		ctx.Log.Fatal(err.Error())
	}
	defer file_w.Close()
	count := int(fileInfo.Size()) / buff_len
	if int(fileInfo.Size())%buff_len > 0 {
		count += 1
	}
	for i := 0; i < count; i++ {
		if i != count-1 {
			n, err := file_r.Read(buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != buff_len {
				ctx.Log.Fatal("[dec] error in reading from file")
			}
			n, err = ctx.Decrypt(buff, buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != buff_len {
				ctx.Log.Fatal("[dec] error in encrypting file")
			}
			n, err = file_w.Write(buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != buff_len {
				ctx.Log.Fatal("[dec] error in writing into file")
			}
		} else {
			n, err := file_r.Read(buff)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			last_part := buff[:n]
			ln, err := ctx.DecryptLast(last_part, &last_part)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			n, err = file_w.Write(last_part)
			if err != nil {
				ctx.Log.Fatal(err.Error())
			}
			if n != ln {
				ctx.Log.Fatal("[dec_last] error in writing into file")
			}
		}
	}
}

func main() {
	if len(os.Args) == 1 {
		fmt.Println("Usage: " + os.Args[0] + " CONFIG")
		os.Exit(1)
	}

	conf, err := utils.ReadConfig(os.Args[1])
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

	l, err := utils.NewLog(conf.LogFile)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

	if conf.EnableHashCheck {
		hash_bdata := manage.BuildData{LEString: &conf.SHA256HashLE}
		h_t, err := manage.BuildFrom(&hash_bdata, manage.BuildFromLEString, 32)
		if err != nil {
			l.Fatal(err.Error())
		}
		check, err := utils.CheckFile(h_t, os.Args[0])
		if err != nil {
			l.Fatal("Hash check error")
		}
		if !check {
			l.Fatal("Hash check fail")
		}
	}

	settings := crypto.CryptoSettings{}
	settings.Mode = crypto.ModeCBC
	settings.Base = crypto.BaseAlgorithmMagma
	settings.AddType = crypto.AdderType2
	switch conf.Form {
	case "Random":
		settings.KeySetting.Method = manage.BuildFromRandom
		settings.IVSetting.Method = manage.BuildFromRandom
	case "BEString":
		settings.KeySetting.Method = manage.BuildFromBEString
		settings.KeySetting.Data = manage.BuildData{BEString: &conf.Key}
		settings.IVSetting.Method = manage.BuildFromBEString
		settings.IVSetting.Data = manage.BuildData{BEString: &conf.IV}
		settings.IVSetting.Len = len(conf.IV) / 2
	case "LEString":
		settings.KeySetting.Method = manage.BuildFromLEString
		settings.KeySetting.Data = manage.BuildData{LEString: &conf.Key}
		settings.IVSetting.Method = manage.BuildFromLEString
		settings.IVSetting.Data = manage.BuildData{LEString: &conf.IV}
	case "File":
		settings.KeySetting.Method = manage.BuildFromFile
		settings.KeySetting.Data = manage.BuildData{File: &conf.Key}
		settings.IVSetting.Method = manage.BuildFromFile
		settings.IVSetting.Data = manage.BuildData{File: &conf.IV}
	}

	mng := crypto.NewCryptoManager(&settings, l)
	if mng == nil {
		l.Fatal("[main] error init crypto module")
	}

	if conf.TestMode == "1" {
		fmt.Println("Test mode 1")
		fmt.Printf("File: %s\n", conf.FileIn)
		var enc_time int64 = 0
		var dec_time int64 = 0

		start := time.Now().UnixNano()
		ctx := mng.NewCryptoCtx(&settings)
		if ctx == nil {
			l.Fatal("[main] error init crypto ctx")
		}

		if conf.BufferLen%ctx.DataAlignment() != 0 {
			ctx.Log.Fatal("Incorrect buffer len, alignment " +
				strconv.FormatInt(int64(ctx.DataAlignment()), 10))
		}

		EncryptFile(conf.FileIn, conf.FileOut, ctx, conf.BufferLen)
		mng.FreeCryptoCtx(ctx)
		end := time.Now().UnixNano()
		enc_time = end - start

		start = time.Now().UnixNano()
		ctx = mng.NewCryptoCtx(&settings)
		if ctx == nil {
			l.Fatal("[main] error init crypto ctx")
		}
		DecryptFile(conf.FileOut, conf.FileOut+".dec", ctx, conf.BufferLen)
		mng.FreeCryptoCtx(ctx)
		end = time.Now().UnixNano()
		dec_time = end - start
		fmt.Printf("Encryption time: %f s\n", float64(enc_time)/1000000000)
		fmt.Printf("Decryption time: %f s\n", float64(dec_time)/1000000000)
	} else if conf.TestMode == "2" {
		fmt.Println("Test mode 2")
		fmt.Printf("Blocks: %d\n", conf.BlocksCount)
		ctx := mng.NewCryptoCtx(&settings)
		if ctx == nil {
			l.Fatal("[main] error init crypto ctx")
		}

		iv := ctx.IV
		ivbdata := manage.BuildData{Bytes: &iv}
		settings.IVSetting.Data = ivbdata
		settings.IVSetting.Method = manage.BuildFromBytes
		settings.IVSetting.Len = len(iv)
		key := make([]byte, ctx.Key.Len())
		keybdata := manage.BuildData{Bytes: &key}
		settings.KeySetting.Data = keybdata

		bdata := manage.BuildData{}
		data, err := manage.BuildFrom(&bdata, manage.BuildFromRandom, int(conf.BlocksCount)*ctx.DataAlignment())
		if err != nil {
			ctx.Log.Fatal("Gen data error")
		}

		iter_count := 1000000 / conf.BlocksCount
		var i int64 = 0
		var enc_time int64 = 0
		var dec_time int64 = 0

		for ; i < iter_count; i++ {
			mng.FreeCryptoCtx(ctx)

			start := time.Now().UnixNano()
			settings.KeySetting.Method = manage.BuildFromRandom
			ctx = mng.NewCryptoCtx(&settings)
			if ctx == nil {
				l.Fatal("[main] error init crypto ctx")
			}

			ld, err := ctx.EncryptLast(data, &data)
			if err != nil {
				ctx.Log.Fatal("encryption data error")
			}
			if ld != int(conf.BlocksCount+1)*(ctx.DataAlignment()) {
				ctx.Log.Fatal("len encryption data error")
			}
			end := time.Now().UnixNano()
			enc_time += end - start

			settings.KeySetting.Method = manage.BuildFromBytes
			subtle.ConstantTimeCopy(1, key, ctx.Key.Data())
			mng.FreeCryptoCtx(ctx)

			start = time.Now().UnixNano()
			ctx = mng.NewCryptoCtx(&settings)
			if ctx == nil {
				l.Fatal("[main] error init crypto ctx")
			}
			ld, err = ctx.DecryptLast(data, &data)
			if err != nil {
				ctx.Log.Fatal("decryption data error")
			}
			if ld != int(conf.BlocksCount)*(ctx.DataAlignment()) {
				ctx.Log.Fatal("len decryption data error")
			}
			end = time.Now().UnixNano()
			dec_time += end - start
		}
		fmt.Printf("Encryption time: %f\n", float64(enc_time)/1000000000)
		fmt.Printf("Decryption time: %f\n", float64(dec_time)/1000000000)
	} else {
		l.Fatal("unsupported test mode")
	}
}
