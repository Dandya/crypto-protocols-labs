package utils

import (
	"errors"
	"log"
	"os"
)

type Log struct {
}

func NewLog(path string) (*Log, error) {
	if len(path) > 0 {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, errors.New("Log: '" + path + "' : " + err.Error())
		}

		log.SetOutput(file)
	}

	return &Log{}, nil
}

func (*Log) Info(msg string) {
	log.Print("[Info] " + msg)
}

func (*Log) Error(msg string) {
	log.Print("[Error] " + msg)
}

func (*Log) Fatal(msg string) {
	log.Fatal("[Fatal] " + msg)
}
