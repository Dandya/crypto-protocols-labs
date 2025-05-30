package utils

import (
	"errors"
	"os"

	"github.com/pelletier/go-toml"
)

type Data struct {
	Form  string
	Value string
	Len   int
}

type LabFirst struct {
	Form        string
	Key         string
	IV          string
	BufferLen   int
	FileIn      string
	FileOut     string
	TestMode    string
	BlocksCount int64
}

type LabSecond struct {
	Form  string
	Key   string
	IV    string
	Label Data
	Seed  Data
}

type LabThird struct {
	BytesCount int
	FileName   string
	Buffer     int
}

type Config struct {
	LogFile         string
	EnableHashCheck bool
	HashLE          string
	Lab1            LabFirst
	Lab2            LabSecond
	Lab3            LabThird
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
