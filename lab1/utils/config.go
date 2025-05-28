package utils

import (
	"errors"
	"os"

	"github.com/pelletier/go-toml"
)

type Config struct {
	LogFile         string
	EnableHashCheck bool
	HashLE          string
	Form            string
	Key             string
	IV              string
	BufferLen       int
	FileIn          string
	FileOut         string
	TestMode        string
	BlocksCount     int64
	// unused
	KeyTimeLife int
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
