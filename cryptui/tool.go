package cryptui

import (
	"github.com/ddkwork/crypt/packetHeadToGo"
	"github.com/ddkwork/crypt/unixTimestampConverter"
	"github.com/ddkwork/golibrary/src/stream/tool"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type objectTool struct {
	//todo run JavaScript
	src            *widget.Entry
	dst            *widget.Entry
	low            *widget.Check  //大小写
	space          *widget.Button //去空格
	swap           *widget.Button //逆序
	head           *widget.Button //包头
	timeStamp      *widget.Button //时间戳
	isTimeStampHex *widget.Check  //
	//todo hex string to hex dump  to hex string  space insert
}

func newObjectTool() *objectTool {
	f := &objectTool{
		src: &widget.Entry{
			DisableableWidget: widget.DisableableWidget{},
			Text:              "",
			TextStyle:         fyne.TextStyle{},
			PlaceHolder:       "convert src",
			OnChanged:         nil,
			OnSubmitted:       nil,
			Password:          false,
			MultiLine:         true,
			Wrapping:          0,
			Validator:         nil,
			CursorRow:         0,
			CursorColumn:      0,
			OnCursorChanged:   nil,
			ActionItem:        nil,
		},
		dst: &widget.Entry{
			DisableableWidget: widget.DisableableWidget{},
			Text:              "",
			TextStyle:         fyne.TextStyle{},
			PlaceHolder:       "convert dst",
			OnChanged:         nil,
			OnSubmitted:       nil,
			Password:          false,
			MultiLine:         true,
			Wrapping:          0,
			Validator:         nil,
			CursorRow:         0,
			CursorColumn:      0,
			OnCursorChanged:   nil,
			ActionItem:        nil,
		},
		low:            widget.NewCheck("大写", nil),
		space:          widget.NewButton("去空格", nil),
		swap:           widget.NewButton("逆序", nil),
		head:           widget.NewButton("charles head", nil),
		timeStamp:      widget.NewButton("时间戳转换", nil),
		isTimeStampHex: widget.NewCheck("hex utc", nil),
		//todo add hexdump
	}
	a := packetHeadToGo.New()
	f.low.OnChanged = func(b bool) {
		upper := strings.ToUpper(f.src.Text)
		f.src.SetText(upper)
	}
	f.space.OnTapped = func() {
		space := strings.Replace(f.src.Text, " ", "", -1) // 去除空格
		//str = strings.Replace(str, "\n", "", -1) // 去除换行符
		f.src.SetText(space)
	}
	f.swap.OnTapped = func() {
		array := tool.Swap().Bytes([]byte(f.src.Text)) //todo rename
		f.src.SetText(string(array))
	}
	f.head.OnTapped = func() {
		if !a.Convert(f.src.Text) {
			return
		}
		f.dst.SetText(a.String())
	}
	t := unixTimestampConverter.New()
	f.timeStamp.OnTapped = func() {
		f.dst.SetText(t.FromInteger(f.src.Text))
	}
	f.isTimeStampHex.OnChanged = func(b bool) {
		f.dst.SetText(t.FromInteger(f.src.Text))
	}
	return f
}

func (o *objectTool) Form() fyne.CanvasObject {
	right := container.NewGridWithColumns(1, o.low, o.space, o.swap, o.head, o.timeStamp, o.isTimeStampHex)
	left := container.NewGridWithColumns(1, o.src, o.dst)
	return container.NewHSplit(left, right)
}
