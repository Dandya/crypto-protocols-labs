package utils

import "math/rand"

func GetRandomInt(m int) int {
	return rand.Intn(m)
}
