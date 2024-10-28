package tool

import (
	"math/big"
)

type (
	Interface interface {
		// big calc
	}
	object struct{}
)

var Default = New()

func New() Interface { return &object{} }

func fromBase10(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 10)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}

func fromBase16(base10 string) *big.Int {
	i, ok := new(big.Int).SetString(base10, 16)
	if !ok {
		panic("bad number: " + base10)
	}
	return i
}
