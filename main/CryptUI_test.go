package main

import (
	"testing"

	"github.com/goradd/maps"

	"github.com/ddkwork/golibrary/stream"
)

func TestName(t *testing.T) {
	g := stream.NewGeneratedFile()
	m := new(maps.SafeSliceMap[string, string])
	m.Set("Symmetry", "symmetry")
	m.Set("Asymmetrical", "asymmetrical")
	m.Set("Hash", "hash")
	m.Set("Encoding", "encoding")
	m.Set("Tool", "Tool")
	g.EnumTypes("Crypt", m)

	m.Clear()
	m.Set("Aes", "Aes")
	m.Set("Des", "Des")
	m.Set("Des3 ", "Des3 ")
	m.Set("Tea", "Tea")
	m.Set("Blowfish", "Blowfish")
	m.Set("TwoFish", "TwoFish")
	m.Set("Rc4", "Rc4")
	m.Set("Rc2", "Rc2")
	m.Set("Rsa", "Rsa")
	m.Set("Ecc", "Ecc")
	m.Set("Dsa", "Dsa")
	m.Set("Pgp", "Pgp")
	m.Set("Sm4", "Sm4")
	m.Set("Sm2", "Sm2")
	m.Set("Hmac", "Hmac")
	m.Set("hashAll", "hashAll")
	m.Set("Base64", "Base64")
	m.Set("Base32", "Base32")
	m.Set("Gzip", "Gzip")
	m.Set("trimSpace", "trimSpace")
	m.Set("swap", "swap")
	m.Set("request header", "request header")
	m.Set("timeStamp", "timeStamp")
	g.EnumTypes("CryptName", m)
}
