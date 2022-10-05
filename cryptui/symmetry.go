package cryptui

import (
	"fyne.io/fyne/v2"
	"github.com/ddkwork/crypt/src/aes"
	"github.com/ddkwork/crypt/src/des"
	"github.com/ddkwork/golibrary/src/stream"
)

func (o *object) aesCanvasObject() fyne.CanvasObject {
	f := clone()
	a := aes.New()
	f.encode.OnTapped = func() {
		encrypt := a.Encrypt(stream.NewHexString(f.src.Text()), stream.NewHexString(f.key.Text()))
		f.dst.SetText(encrypt.HexString())
	}
	f.decode.OnTapped = func() {
		dst := a.Decrypt(stream.NewHexString(f.dst.Text()), stream.NewHexString(f.key.Text()))
		f.src.SetText(dst.HexString())
	}
	return f.Form()
}

func (o *object) desCanvasObject() fyne.CanvasObject {
	f := clone()
	a := des.New()
	f.encode.OnTapped = func() {
		encrypt := a.Encrypt(stream.NewHexString(f.src.Text()), stream.NewHexString(f.key.Text()))
		f.dst.SetText(encrypt.HexString())
	}
	f.decode.OnTapped = func() {
		dst := a.Decrypt(stream.NewHexString(f.dst.Text()), stream.NewHexString(f.key.Text()))
		f.src.SetText(dst.HexString())
	}
	return f.Form()
}

func (o *object) des3CanvasObject() fyne.CanvasObject {
	f := clone()
	f.src.Text()
	//...
	return f.Form()
}

func (o *object) teaCanvasObject() fyne.CanvasObject {
	f := clone()
	f.src.Text()
	//...
	return f.Form()
}

func (o *object) blofishCanvasObject() fyne.CanvasObject {
	f := clone()
	f.src.Text()
	//...
	return f.Form()
}

func (o *object) twofishCanvasObject() fyne.CanvasObject {
	f := clone()
	f.src.Text()
	//...
	return f.Form()
}

func (o *object) rc4CanvasObject() fyne.CanvasObject {
	f := clone()
	f.src.Text()
	//...
	return f.Form()
}
