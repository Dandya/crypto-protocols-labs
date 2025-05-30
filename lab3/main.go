package main

import (
	"crypto/rand"
	"fmt"
	"gost_magma_cbc/crypto/drbg/hdrbg"
	"gost_magma_cbc/crypto/hash/streebog"
	"gost_magma_cbc/crypto/manage"
	"gost_magma_cbc/utils"
	"os"
	"time"
)

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

	l.Info("lab3: start work")

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

	if conf.Lab3.Mode == 1 {
		file_w, err := os.OpenFile(conf.Lab3.FileName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
		if err != nil {
			l.Fatal(err.Error())
		}
		count := conf.Lab3.BytesCount / conf.Lab3.Buffer
		mod := conf.Lab3.BytesCount % conf.Lab3.Buffer

		buff := make([]byte, conf.Lab3.Buffer)
		d, err := hdrbg.NewHashDrbgPrng(streebog.New256, rand.Reader, 32, hdrbg.SECURITY_LEVEL_TWO, nil)
		if err != nil {
			l.Fatal(err.Error())
		}

		start := time.Now().UnixNano()
		for i := count; i > 0; i-- {
			d.Read(buff[:])
			file_w.Write(buff[:])
		}
		d.Read(buff[:mod])
		file_w.Write(buff[:mod])
		end := time.Now().UnixNano()
		fmt.Printf("Processed time for %d: %f s -> %f s\n", conf.Lab3.BytesCount,
			float64(end-start)/1000000000, float64(end-start)/(1000000000*float64(count)))
	} else if conf.Lab3.Mode == 2 {
		min := 1000
		max := 10000
		drbg, err := hdrbg.NewHashDrbgPrng(streebog.New256, rand.Reader, 32, 2, nil)
		if err != nil {
			l.Fatal(err.Error())
		}
		rand_bdata := manage.BuildData{Prng: drbg}
		count := min + utils.GetRandomInt(max-min)
		start := time.Now().UnixNano()
		for i := count; i > 0; i-- {
			_, err := manage.BuildFrom(&rand_bdata, manage.BuildFromRandom, 64)
			if err != nil {
				l.Fatal(err.Error())
			}
		}
		end := time.Now().UnixNano()
		fmt.Printf("Processed time for %d: %f s -> %f s\n", count,
			float64(end-start)/1000000000, float64(end-start)/(1000000000*float64(count)))
	} else {
		l.Error("main: unknown method")

	}
	l.Info("lab3: end work")
}
