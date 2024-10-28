package base32

import (
	"encoding/base32"
)

type (
	Interface interface {
		StdEncoding() *base32.Encoding
		HexEncoding() *base32.Encoding
	}

	object struct {
		errorInfo string
		err       error
		stack     string
	}
)

func (o *object) StdEncoding() *base32.Encoding { return base32.StdEncoding }
func (o *object) HexEncoding() *base32.Encoding { return base32.HexEncoding }

var Default = New()

func New() Interface { return &object{} }
