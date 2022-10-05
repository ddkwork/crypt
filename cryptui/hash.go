package cryptui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/ddkwork/crypt/src/hash"
	"github.com/ddkwork/crypt/src/hmac"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/fpabl0/sparky-go/swid"
)

func (o *object) hmacCanvasObject() fyne.CanvasObject {
	f := clone()
	f.decode.Hide()
	h := hmac.New()
	newSelect := widget.NewSelect(
		[]string{
			typeCrypt.hmacSha1(),
			typeCrypt.hmacSha224(),
			typeCrypt.hmacSha256(),
			typeCrypt.hmacSha384(),
			typeCrypt.hmacSha512(),
		},
		func(s string) {
			switch s {
			case typeCrypt.hmacSha1():
				sha1 := h.HmacSha1(f.src.Text(), f.key.Text())
				f.dst.SetText(sha1.HexString())
			case typeCrypt.hmacSha224():
				sha224 := h.HmacSha224(f.src.Text(), f.key.Text())
				f.dst.SetText(sha224.HexString())
			case typeCrypt.hmacSha256():
				sha256 := h.HmacSha256(f.src.Text(), f.key.Text())
				f.dst.SetText(sha256.HexString())
			case typeCrypt.hmacSha384():
				sha384 := h.HmacSha384(f.src.Text(), f.key.Text())
				f.dst.SetText(sha384.HexString())
			case typeCrypt.hmacSha512():
				sha512 := h.HmacSha512(f.src.Text(), f.key.Text())
				f.dst.SetText(sha512.HexString())
			}
		},
	)
	return container.NewVBox(newSelect, f.Form())
}

func (o *object) hashCanvasObject() fyne.CanvasObject {
	line := container.NewGridWithColumns(1)
	objs := map[string]*swid.TextFormField{
		"src":              swid.NewTextFormField("src", ""),
		typeCrypt.md2():    swid.NewTextFormField(typeCrypt.md2(), ""),
		typeCrypt.md4():    swid.NewTextFormField(typeCrypt.md4(), ""),
		typeCrypt.md5():    swid.NewTextFormField(typeCrypt.md5(), ""),
		typeCrypt.sha1():   swid.NewTextFormField(typeCrypt.sha1(), ""),
		typeCrypt.sha224(): swid.NewTextFormField(typeCrypt.sha224(), ""),
		typeCrypt.sha256(): swid.NewTextFormField(typeCrypt.sha256(), ""),
		typeCrypt.sha384(): swid.NewTextFormField(typeCrypt.sha384(), ""),
		typeCrypt.sha512(): swid.NewTextFormField(typeCrypt.sha512(), ""),
	}
	h := hash.New()
	for _, canvasObject := range objs {
		line.Add(canvasObject)
	}
	objs["src"].OnChanged = func(s string) {
		if !h.Md2(s) {
			objs[typeCrypt.md2()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.md2()].SetText(h.Sum())
		}
		if !h.Md4(s) {
			objs[typeCrypt.md4()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.md4()].SetText(h.Sum())
		}
		if !h.Md5(s) {
			objs[typeCrypt.md5()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.md5()].SetText(h.Sum())
		}

		if !h.Sha1(s) {
			objs[typeCrypt.sha1()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.sha1()].SetText(h.Sum())
		}
		if !h.Sha224(s) {
			objs[typeCrypt.sha224()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.sha224()].SetText(h.Sum())
		}
		if !h.Sha256(s) {
			objs[typeCrypt.sha256()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.sha256()].SetText(h.Sum())
		}
		if !h.Sha384(s) {
			objs[typeCrypt.sha384()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.sha384()].SetText(h.Sum())
		}
		if !h.Sha512(s) {
			objs[typeCrypt.sha512()].SetText(mylog.Body())
		} else {
			objs[typeCrypt.sha512()].SetText(h.Sum())
		}
	}
	return container.NewVScroll(line)
}

//func (o *object) hashCanvasObject1() fyne.CanvasObject {
//    src := swid.NewTextFormField("src", "")
//    md2 := swid.NewTextFormField(typeCrypt.md2(), "")
//    md4 := swid.NewTextFormField(typeCrypt.md4(), "")
//    md5 := swid.NewTextFormField(typeCrypt.md5(), "")
//    sha1 := swid.NewTextFormField(typeCrypt.sha1(), "")
//    sha224 := swid.NewTextFormField(typeCrypt.sha224(), "")
//    sha256 := swid.NewTextFormField(typeCrypt.sha256(), "")
//    sha384 := swid.NewTextFormField(typeCrypt.sha384(), "")
//    sha512 := swid.NewTextFormField(typeCrypt.sha512(), "")
//    h := hash.New()
//    src.OnChanged = func(s string) {
//        if !h.Md2(s) {
//            md2.SetText(mylog.Body())
//        } else {
//            md2.SetText(h.Sum())
//        }
//        if !h.Md4(s) {
//            md4.SetText(mylog.Body())
//        } else {
//            md4.SetText(h.Sum())
//        }
//        if !h.Md5(s) {
//            md5.SetText(mylog.Body())
//        } else {
//            md5.SetText(h.Sum())
//        }
//
//        if !h.Sha1(s) {
//            sha1.SetText(mylog.Body())
//        } else {
//            sha1.SetText(h.Sum())
//        }
//        if !h.Sha224(s) {
//            sha224.SetText(mylog.Body())
//        } else {
//            sha224.SetText(h.Sum())
//        }
//        if !h.Sha256(s) {
//            sha256.SetText(mylog.Body())
//        } else {
//            sha256.SetText(h.Sum())
//        }
//        if !h.Sha384(s) {
//            sha384.SetText(mylog.Body())
//        } else {
//            sha384.SetText(h.Sum())
//        }
//        if !h.Sha512(s) {
//            sha512.SetText(mylog.Body())
//        } else {
//            sha512.SetText(h.Sum())
//        }
//    }
//    columns := container.NewGridWithColumns(1,
//        src,
//        md2,
//        md4,
//        md5,
//        sha1,
//        sha224,
//        sha256,
//        sha384,
//        sha512,
//    )
//    return container.NewVScroll(columns)
//}
