package main

import (
	"errors"
	"fmt"
	"gost_magma_cbc/crypto"
	"gost_magma_cbc/crypto/kdf"
	"gost_magma_cbc/crypto/manage"
	"gost_magma_cbc/crypto/models"
	"gost_magma_cbc/utils"
	"math/rand"
	"os"
	"time"
)

func BuildData(d *utils.Data) ([]byte, error) {
	switch d.Form {
	case "Random":
		bdata := manage.BuildData{}
		data, err := manage.BuildFrom(&bdata, manage.BuildFromRandom, d.Len)
		if err != nil {
			return nil, err
		}
		return data, nil
	case "BEString":
		bdata := manage.BuildData{BEString: &d.Value}
		data, err := manage.BuildFrom(&bdata, manage.BuildFromBEString, d.Len)
		if err != nil {
			return nil, err
		}
		return data, nil
	case "LEString":
		bdata := manage.BuildData{LEString: &d.Value}
		data, err := manage.BuildFrom(&bdata, manage.BuildFromLEString, d.Len)
		if err != nil {
			return nil, err
		}
		return data, nil
	case "File":
		bdata := manage.BuildData{File: &d.Value}
		data, err := manage.BuildFrom(&bdata, manage.BuildFromFile, d.Len)
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		return nil, errors.New("unknown data form")
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

	l.Info("lab2: start work")

	if conf.EnableHashCheck {
		hash_bdata := manage.BuildData{LEString: &conf.HashLE}
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
	settings.Log = l
	switch conf.Lab2.Form {
	case "Random":
		settings.KeySetting.Method = manage.BuildFromRandom
		settings.IVSetting.Method = manage.BuildFromRandom
	case "BEString":
		settings.KeySetting.Method = manage.BuildFromBEString
		settings.KeySetting.Data = manage.BuildData{BEString: &conf.Lab2.Key}
		settings.IVSetting.Method = manage.BuildFromBEString
		settings.IVSetting.Data = manage.BuildData{BEString: &conf.Lab2.IV}
		settings.IVSetting.Len = len(conf.Lab2.IV) / 2
	case "LEString":
		settings.KeySetting.Method = manage.BuildFromLEString
		settings.KeySetting.Data = manage.BuildData{LEString: &conf.Lab2.Key}
		settings.IVSetting.Method = manage.BuildFromLEString
		settings.IVSetting.Data = manage.BuildData{LEString: &conf.Lab2.IV}
		settings.IVSetting.Len = len(conf.Lab2.IV) / 2
	case "File":
		settings.KeySetting.Method = manage.BuildFromFile
		settings.KeySetting.Data = manage.BuildData{File: &conf.Lab2.Key}
		settings.IVSetting.Method = manage.BuildFromFile
		settings.IVSetting.Data = manage.BuildData{File: &conf.Lab2.IV}
	}

	mng := crypto.NewCryptoManager(&settings)
	if mng == nil {
		l.Fatal("lab2: error init crypto module")
	}

	ctx := mng.NewCryptoCtx(&settings)
	if ctx == nil {
		l.Fatal("lab2: error init crypto ctx")
	}

	// Настройка KDF
	k := kdf.NewKDF256()

	// Настройка ключа
	key_data := ctx.Key.Data()


	// Настройка label
	label, err := BuildData(&conf.Lab2.Label)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(2)
	}

	count := 10000 + rand.Int31n(1000000 - 10000)

	start := time.Now().UnixNano()
	for i:=count; i > 0; i-- {
		// Настройка seed
		seed, err := BuildData(&conf.Lab2.Seed)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(2)
		}
		bkdf := manage.BuildData{Kdf: models.KDFParams{Kdf: k, Key: key_data, Label: label, Seed: seed}}
		key_data, err = manage.BuildFrom(&bkdf, manage.BuildFromKDF, ctx.Key.Len())
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(3)
		}
	}
	end := time.Now().UnixNano()
	fmt.Printf("Processed time for %d: %f s -> %f s\n", count,
			float64(end-start)/1000000000, float64(end-start)/(1000000000*float64(count)))
	l.Info("lab2: end work")
}
