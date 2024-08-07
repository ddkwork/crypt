package main

import (
	"strings"

	"golang.org/x/exp/constraints"
)

// Code generated by GeneratedFile enum - DO NOT EDIT.

type CryptKind byte

const (
	SymmetryKind CryptKind = iota
	AsymmetricalKind
	HashKind
	EncodingKind
	ToolKind
	InvalidCryptKind
)

func ConvertInteger2CryptKind[T constraints.Integer](v T) CryptKind {
	return CryptKind(v)
}

func (k CryptKind) AssertKind(kinds string) CryptKind {
	for _, kind := range k.Kinds() {
		if strings.ToLower(kinds) == strings.ToLower(kind.String()) {
			return kind
		}
	}
	return InvalidCryptKind
}

func (k CryptKind) String() string {
	switch k {
	case SymmetryKind:
		return "Symmetry"
	case AsymmetricalKind:
		return "Asymmetrical"
	case HashKind:
		return "Hash"
	case EncodingKind:
		return "Encoding"
	case ToolKind:
		return "Tool"
	default:
		return "InvalidCryptKind"
	}
}

func (k CryptKind) Keys() []string {
	return []string{
		"Symmetry",
		"Asymmetrical",
		"Hash",
		"Encoding",
		"Tool",
	}
}

func (k CryptKind) Kinds() []CryptKind {
	return []CryptKind{
		SymmetryKind,
		AsymmetricalKind,
		HashKind,
		EncodingKind,
		ToolKind,
	}
}

func (k CryptKind) SvgFileName() string {
	switch k {
	case SymmetryKind:
		return "Symmetry"
	case AsymmetricalKind:
		return "Asymmetrical"
	case HashKind:
		return "Hash"
	case EncodingKind:
		return "Encoding"
	case ToolKind:
		return "Tool"
	default:
		return "InvalidCryptKind"
	}
}
