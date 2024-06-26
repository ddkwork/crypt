package main

import (
	"testing"

	"github.com/ddkwork/golibrary/stream"
)

func TestName(t *testing.T) {
	g := stream.NewGeneratedFile()
	g.Enum("Crypt", []string{
		"Symmetry",
		"Asymmetrical",
		"Hash",
		"Encoding",
		"Tool",
	}, nil)
}
