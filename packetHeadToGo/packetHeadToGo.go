package packetHeadToGo

import (
	"bytes"
	"go/format"
	"strconv"
	"strings"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

// 自动提取charles的包头为go map
type (
	Interface interface {
		Convert(src string) (ok bool)
		String() string
		Map() map[string]string
	}
	object struct {
		m map[string]string // should be http.req.head type:map string []string,but go not anny code in http pkg
	}
)

func (o *object) Convert(src string) (ok bool) {
	for line := range stream.ReadFileToLines(src) {
		if !strings.Contains(line, ":") { // skip get post
			continue
		}
		index := strings.IndexByte(line, ':')
		key := line[:index]
		value := line[index+1:]
		// split := strings.Split(string(line), ":")   http:// ...  bug
		o.m[key] = strings.TrimSpace(value)
	}
	return true
}

func (o *object) String() string { // bug
	buffer := bytes.NewBuffer(nil)
	buffer.WriteString("head := map[string]string{")
	buffer.WriteByte('\n')
	for k, v := range o.m {
		buffer.WriteString(strconv.Quote(k))
		buffer.WriteString(":")
		buffer.WriteString(strconv.Quote(v))
		buffer.WriteString(",")
		buffer.WriteByte('\n')
	}
	buffer.WriteString("}")
	source := mylog.Check2(format.Source(buffer.Bytes()))

	return string(source)
}

func (o *object) Map() map[string]string {
	return o.m
}

func New() Interface {
	return &object{
		m: make(map[string]string),
	}
}
