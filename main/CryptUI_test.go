package main

import (
	"testing"

	"github.com/ddkwork/golibrary/safemap"
	"github.com/ddkwork/golibrary/stream"
)

func TestName(t *testing.T) {
	g := stream.NewGeneratedFile()
	m := safemap.NewOrdered[string, string](func(yield func(string, string) bool) {
		yield("Symmetry", "Symmetry")
		yield("Asymmetrical", "Asymmetrical")
		yield("Hash", "Hash")
		yield("Encoding", "Encoding")
		yield("Tool", "Tool")
	})
	g.EnumTypes("Crypt", m)

	m.Reset()
	m.Collect(func(yield func(string, string) bool) {
		yield("Aes", "Aes")
		yield("Des", "Des")
		yield("Des3", "Des3")
		yield("Tea", "Tea")
		yield("Blowfish", "Blowfish")
		yield("TwoFish", "TwoFish")
		yield("Rc4", "Rc4")
		yield("Rc2", "Rc2")
		yield("Rsa", "Rsa")
		yield("Ecc", "Ecc")
		yield("Dsa", "Dsa")
		yield("Pgp", "Pgp")
		yield("Sm4", "Sm4")
		yield("Sm2", "Sm2")
		yield("Hmac", "Hmac")
		yield("HashAll", "HashAll")
		yield("Base64", "Base64")
		yield("Base32", "Base32")
		yield("Gzip", "Gzip")
		yield("TrimSpace", "TrimSpace")
		yield("Swap", "Swap")
		yield("RequestHeader", "RequestHeader")
		yield("TimeStamp", "TimeStamp")
	})
	g.EnumTypes("CryptName", m)
}
