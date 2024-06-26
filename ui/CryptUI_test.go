package main

import (
	"testing"

	"github.com/ddkwork/golibrary/stream"
)

func TestName(t *testing.T) {
	g := stream.NewGeneratedFile()
	g.Enum("CryptNode", []string{
		"SymmetryNode",
		"AsymmetricalNode",
		"HashNode",
		"EncodingNode",
		"ToolNode",
	}, nil)
	g.Enum("Symmetry", []string{
		"Aes",
		"Des",
		"Des3",
		"Tea",
		"Blowfish",
		"TwoFish",
		"Rc4",
		"Rc2",
	}, nil)
	g.Enum("Asymmetrical", []string{
		"rsa",
	}, nil)
	g.Enum("Hash", []string{
		"Hmac",
		"hashAll",
	}, nil)
	g.Enum("Encoding", []string{
		"Base64",
		"Base32",
		"Gzip",
	}, nil)
	g.Enum("tool", []string{
		"trimSpace",
		"swap",
		"request header",
		"timeStamp",
	}, nil)
}
