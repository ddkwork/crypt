package main

import (
	"strings"

	"golang.org/x/exp/constraints"
)

// Code generated by GeneratedFile enum - DO NOT EDIT.

type SymmetryKind byte

const (
	AesKind SymmetryKind = iota
	DesKind
	Des3Kind
	TeaKind
	BlowfishKind
	TwoFishKind
	Rc4Kind
	Rc2Kind
	InvalidSymmetryKind
)

func ConvertInteger2SymmetryKind[T constraints.Integer](v T) SymmetryKind {
	return SymmetryKind(v)
}

func (k SymmetryKind) AssertKind(kinds string) SymmetryKind {
	for _, kind := range k.Kinds() {
		if strings.ToLower(kinds) == strings.ToLower(kind.String()) {
			return kind
		}
	}
	return InvalidSymmetryKind
}

func (k SymmetryKind) String() string {
	switch k {
	case AesKind:
		return "Aes"
	case DesKind:
		return "Des"
	case Des3Kind:
		return "Des3"
	case TeaKind:
		return "Tea"
	case BlowfishKind:
		return "Blowfish"
	case TwoFishKind:
		return "TwoFish"
	case Rc4Kind:
		return "Rc4"
	case Rc2Kind:
		return "Rc2"
	default:
		return "InvalidSymmetryKind"
	}
}

func (k SymmetryKind) Keys() []string {
	return []string{
		"Aes",
		"Des",
		"Des3",
		"Tea",
		"Blowfish",
		"TwoFish",
		"Rc4",
		"Rc2",
		"InvalidSymmetryKind",
	}
}

func (k SymmetryKind) Kinds() []SymmetryKind {
	return []SymmetryKind{
		AesKind,
		DesKind,
		Des3Kind,
		TeaKind,
		BlowfishKind,
		TwoFishKind,
		Rc4Kind,
		Rc2Kind,
		InvalidSymmetryKind,
	}
}

func (k SymmetryKind) SvgFileName() string {
	switch k {
	case AesKind:
		return "Aes"
	case DesKind:
		return "Des"
	case Des3Kind:
		return "Des3"
	case TeaKind:
		return "Tea"
	case BlowfishKind:
		return "Blowfish"
	case TwoFishKind:
		return "TwoFish"
	case Rc4Kind:
		return "Rc4"
	case Rc2Kind:
		return "Rc2"
	default:
		return "InvalidSymmetryKind"
	}
}
