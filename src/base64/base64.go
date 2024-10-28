package base64

import (
	"encoding/base64"
	_ "unsafe"
)

////go:linkname encodeStd encoding/base64.encodeStd
//const Std = ""
//
////go:linkname encodeURL encoding/base64.encodeURL
//var encodeURL string
//
//func init() {
//    println("encodeStd " + Std)
//    println("encodeURL " + encodeURL)
//}

type (
	Interface interface {
		StdEncoding() *base64.Encoding
		URLEncoding() *base64.Encoding
		RawStdEncoding() *base64.Encoding
		RawURLEncoding() *base64.Encoding
		// helper
	}
	object struct {
		errorInfo string
		err       error
		stack     string
		coder
	}
	coder struct {
		stdEncoding    *base64.Encoding
		uRLEncoding    *base64.Encoding
		rawStdEncoding *base64.Encoding
		rawURLEncoding *base64.Encoding
	}
)

func (c *coder) StdEncoding() *base64.Encoding    { return c.stdEncoding }
func (c *coder) URLEncoding() *base64.Encoding    { return c.uRLEncoding }
func (c *coder) RawStdEncoding() *base64.Encoding { return c.rawStdEncoding }
func (c *coder) RawURLEncoding() *base64.Encoding { return c.rawURLEncoding }

var Default = New()

func New() Interface {
	return &object{
		errorInfo: "",
		err:       nil,
		stack:     "",
		coder: coder{
			stdEncoding:    base64.StdEncoding,
			uRLEncoding:    base64.URLEncoding,
			rawStdEncoding: base64.RawStdEncoding,
			rawURLEncoding: base64.RawURLEncoding,
		},
	}
}
