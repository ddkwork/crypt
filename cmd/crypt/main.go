package main

import (
	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"github.com/ddkwork/crypt/cryptui"
	"github.com/ddkwork/golibrary/src/fynelib/fyneTheme"
)

//go:generate  go build .
func main() {
	a := app.NewWithID("com.rows.app")
	a.SetIcon(nil)
	fyneTheme.Dark()
	w := a.NewWindow("app")
	w.Resize(fyne.NewSize(640, 480))
	w.SetMaster()
	w.CenterOnScreen()
	w.SetContent(cryptui.New().CanvasObject(w))
	w.ShowAndRun()
}
