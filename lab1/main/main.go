package main

import (
	"fmt"
	"os"

	"gost_magma_cbc/utils"
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

	fmt.Println(conf.KeysPath)
}