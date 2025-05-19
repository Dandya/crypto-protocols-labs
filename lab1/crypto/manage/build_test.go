package manage

import (
	"os"
	"testing"
)

func TestBuildBEString(t *testing.T) {
	s := "0201"
	b := BuildData{BEString: &s}
	d, err := BuildFrom(&b, BuildFromBEString, 2)
	if err != nil {
		t.Error(err)
	}

	if d[0] != byte(1) || d[1] != byte(2) {
		t.Error("error build data")
	}
}

func TestBuildLEString(t *testing.T) {
	s := "0201"
	b := BuildData{LEString: &s}
	d, err := BuildFrom(&b, BuildFromLEString, 2)
	if err != nil {
		t.Error(err)
	}

	if d[0] != byte(2) || d[1] != byte(1) {
		t.Error("error build data")
	}
}

func TestBuildBytes(t *testing.T) {
	s := []byte{2, 1}
	b := BuildData{Bytes: &s}
	d, err := BuildFrom(&b, BuildFromBytes, 2)
	if err != nil {
		t.Error(err)
	}

	if d[0] != byte(2) || d[1] != byte(1) {
		t.Error("error build data")
	}
}

func TestBuildFile(t *testing.T) {
	f, err := os.Create("test.bin")
	if err != nil {
		t.Error(err)
	}
	defer os.Remove("test.bin")

	s := []byte{2, 1}
	c, err := f.Write(s)
	if err != nil {
		t.Error(err)
	}
	if c != 2 {
		t.Error("write error")
	}
	err = f.Close()
	if err != nil {
		t.Error(err)
	}

	p := "test.bin"
	b := BuildData{File: &p}
	d, err := BuildFrom(&b, BuildFromFile, 2)
	if err != nil {
		t.Error(err)
	}

	if d[0] != byte(2) || d[1] != byte(1) {
		t.Error("error build data")
	}
}

func TestBuildRandom(t *testing.T) {
	b := BuildData{}
	d, err := BuildFrom(&b, BuildFromRandom, 2)
	if err != nil {
		t.Error(err)
	}

	if d[0] == byte(0) && d[1] != byte(0) {
		t.Error("zero data")
	}
}
