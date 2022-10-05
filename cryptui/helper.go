package cryptui

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/fpabl0/sparky-go/swid"
)

type (
	objectTemplate struct {
		src    *swid.TextFormField
		key    *swid.TextFormField
		dst    *swid.TextFormField
		encode *widget.Button
		decode *widget.Button
		tool   *objectTool
	}
)

func (o *objectTemplate) Form() fyne.CanvasObject {
	return widget.NewForm(
		widget.NewFormItem("", o.src),
		widget.NewFormItem("", o.key),
		widget.NewFormItem("", o.dst),
		widget.NewFormItem("", container.NewGridWithColumns(2, o.encode, o.decode)),
		widget.NewFormItem("", layout.NewSpacer()),
		widget.NewFormItem("", layout.NewSpacer()),
		widget.NewFormItem("", o.tool.Form()),
	)
}

func clone() *objectTemplate {
	return &objectTemplate{
		src:    swid.NewTextFormField("src", ""),
		key:    swid.NewTextFormField("key", ""),
		dst:    swid.NewTextFormField("dst", ""),
		encode: widget.NewButton("encode", nil),
		decode: widget.NewButton("decode", nil),
		tool:   newObjectTool(),
	}
}
