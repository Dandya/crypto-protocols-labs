package utils

import (
	"errors"
	"os"

	"github.com/pelletier/go-toml"
)

type Config struct {
	IsKeySave bool
	KeysPath string
	KeyTimeLifeByBlocks bool
	KeyTimeLife int
}

func SetDefault(conf *Config) {

}

func ReadConfig(path string) (*Config, error) {
	conf := &Config{}


	file, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("[reading " + path + "] " + err.Error())
	}


	err = toml.Unmarshal(file, conf)
	if err != nil {
		return nil, errors.New("[parsing toml " + path + "] " + err.Error())
	}

	return conf, nil
	
}