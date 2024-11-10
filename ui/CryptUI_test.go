package main

import (
	"testing"

	"github.com/ddkwork/golibrary/stream"
)

func TestName(t *testing.T) {
	t.Skip()
	g := stream.NewGeneratedFile()
	m := stream.NewOrderedMapFromPairs([]stream.Pair[string, string]{
		{Key: "Symmetry", Value: "symmetry"},
		{Key: "Asymmetrical", Value: "asymmetrical"},
		{Key: "Hash", Value: "hash"},
		{Key: "Encoding", Value: "encoding"},
		{Key: "Tool", Value: "tool"},
	})
	g.EnumTypes("Crypt", m)
	g.EnumTypes("CryptName", []string{
		"Aes",
		"Des",
		"Des3 ",
		"Tea",
		"Blowfish",
		"TwoFish",
		"Rc4",
		"Rc2",

		"Rsa",
		"Ecc",
		"Dsa",
		"Pgp",
		"Sm4",
		"Sm2",

		"Hmac",
		"hashAll",

		"Base64",
		"Base32",
		"Gzip",

		"trimSpace",
		"swap",
		"request header",
		"timeStamp",
	}, nil)
}
