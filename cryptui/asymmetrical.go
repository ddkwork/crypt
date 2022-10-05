package cryptui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ddkwork/crypt/src/rsa"
	"github.com/ddkwork/golibrary/src/stream"
	"github.com/fpabl0/sparky-go/swid"
)

func (o *object) CanvasObjectRsa() fyne.CanvasObject {
	p := swid.NewTextFormField("质数(p)", "")
	q := swid.NewTextFormField("质数(q)", "")
	e := swid.NewTextFormField("指数(e)", "")
	n := swid.NewTextFormField("模数(n)", "")
	d := swid.NewTextFormField("私钥(d)", "")
	m := swid.NewTextFormField("明文(m)", "")
	c := swid.NewTextFormField("密文(c)", "")
	r := rsa.New()
	gridWithColumns := container.NewGridWithColumns(3,
		widget.NewButtonWithIcon("密钥对", theme.ConfirmIcon(), func() {}),
		widget.NewButtonWithIcon("加密", theme.ConfirmIcon(), func() {
			encrypt := r.Encrypt(stream.NewString(m.Text()), n.Text(), e.Text())
			if encrypt == nil {
				return
			}
			c.SetText(encrypt.HexStringUpper())
		}),
		widget.NewButtonWithIcon("解密", theme.CancelIcon(), func() {
			decrypt := r.Decrypt(stream.NewHexString(c.Text()), n.Text(), e.Text(), d.Text())
			if decrypt == nil {
				return
			}
			m.SetText(decrypt.String())
		}),
		widget.NewButtonWithIcon("计算私钥(D)", theme.ConfirmIcon(), func() {
			calcD := r.CalcD(e.Text(), p.Text(), q.Text())
			if calcD == nil {
				return
			}
			d.SetText(calcD.HexStringUpper())
		}),
		widget.NewButtonWithIcon("因式分解(N)", theme.ConfirmIcon(), func() {}),
	)
	note := widget.NewLabel("encode:C=M^e(mod n)   decode:M=C^d(mod n)")
	box := container.NewHBox(layout.NewSpacer(), note)
	return widget.NewForm(
		widget.NewFormItem("", e),
		widget.NewFormItem("", n),
		widget.NewFormItem("", d),
		widget.NewFormItem("", m),
		widget.NewFormItem("", c),
		widget.NewFormItem("", p),
		widget.NewFormItem("", q),
		widget.NewFormItem("", gridWithColumns),
		widget.NewFormItem("", layout.NewSpacer()),
		widget.NewFormItem("", box),
	)
}

func (o *object) CanvasObjectEcc() fyne.CanvasObject {
	return container.NewVBox(widget.NewButton("template", nil))
}
