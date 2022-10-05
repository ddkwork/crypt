package hexStringDump

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/src/stream/tool/file"
	"strings"
)

type (
	Interface interface {
		RemoveOffsetAndAscii() //移除基址或偏移和字符显示
		RemoveNewLine()        //移除换行
		RemoveSpace()          //移除空格
		ToGoBytesSlice()       //go slice
		Convert(src string) (ok bool)
		print()
	}
	object struct {
		lines []string
		ok    bool
	}
)

func (o *object) print() {
	for i, line := range o.lines {
		l.Info(fmt.Sprint(i), line)
	}
}

func (o *object) RemoveOffsetAndAscii() {
	offset := len("08A73200")
	data := len(" 57 61 72 68 61 6D 6D 65 72 20 34 30 2C 30 30 30 ")
	//end := "Warhammer 40,00"
	//取每一行的数据
	for _, line := range o.lines {
		line = line[offset:]
		line = line[:data]
		o.lines = append(o.lines, line)
	}
	o.print()
}

func (o *object) RemoveNewLine() {
	for _, line := range o.lines {
		line = strings.Replace(line, "\n", "", -1)
		o.lines = append(o.lines, line)
	}
	o.print()
}

func (o *object) RemoveSpace() {
	for _, line := range o.lines {
		line = strings.Replace(line, " ", "", -1)
		o.lines = append(o.lines, line)
	}
	o.print()
}

func (o *object) ToGoBytesSlice() {
	o.RemoveNewLine()
	bytes, err := hex.DecodeString(o.lines[0])
	if !mylog.Error(err) {
		return
	}
	l.Struct(bytes)
}

func (o *object) Convert(src string) (ok bool) {
	o.lines, o.ok = file.New().ToLines(bytes.NewBufferString(src))
	o.print()
	return o.ok
}

var (
	Default = New()
	l       = mylog.New()
)

func New() Interface { return &object{} }
