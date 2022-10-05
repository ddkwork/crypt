package cryptui

import (
	"fyne.io/fyne/v2"
	"github.com/ddkwork/crypt/src/base32"
	"github.com/ddkwork/crypt/src/base64"
	"github.com/ddkwork/golibrary/src/stream"
	"github.com/ddkwork/golibrary/src/stream/tool/gzip"
)

func (o *object) Base64CanvasObject() fyne.CanvasObject {
	f := clone()
	f.key.Hide()
	b := base64.New()
	f.encode.OnTapped = func() {
		encrypt := b.StdEncoding().EncodeToString([]byte(f.src.Text()))
		f.dst.SetText(encrypt)
	}
	f.decode.OnTapped = func() {
		src, err := b.StdEncoding().DecodeString(f.dst.Text())
		if err != nil {
			f.src.SetText(err.Error())
		} else {
			f.src.SetText(string(src))
		}
	}
	return f.Form()
}

func (o *object) Base32CanvasObject() fyne.CanvasObject {
	f := clone()
	f.key.Hide()
	b := base32.New()
	f.encode.OnTapped = func() {
		encrypt := b.StdEncoding().EncodeToString([]byte(f.src.Text()))
		f.dst.SetText(encrypt)
	}
	f.decode.OnTapped = func() {
		src, err := b.StdEncoding().DecodeString(f.dst.Text())
		if err != nil {
			f.src.SetText(err.Error())
		} else {
			f.src.SetText(string(src))
		}
	}
	return f.Form()
}

func (o *object) gzipCanvasObject() fyne.CanvasObject {
	f := clone()
	f.encode.Hide()
	f.key.Hide()
	f.encode.Disable()
	a := gzip.New()
	f.decode.OnTapped = func() {
		hexString := stream.NewHexString(f.dst.Text())
		dst := a.Decode(hexString.Bytes())
		f.src.SetText(dst.HexStringUpper())
	}
	return f.Form()
}
