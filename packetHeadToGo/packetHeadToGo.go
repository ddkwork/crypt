package packetHeadToGo

import (
	"bytes"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/src/stream/tool/file"
	"go/format"
	"strconv"
	"strings"
)

// 自动提取charles的包头为go map
type (
	Interface interface {
		Convert(src string) (ok bool)
		String() string
		Map() map[string]string
	}
	object struct {
		m map[string]string //should be http.req.head type:map string []string,but go not anny code in http pkg
	}
)

func (o *object) Convert(src string) (ok bool) {
	lines, b := file.New().ToLines(bytes.NewBufferString(src))
	if !b {
		return
	}
	for _, line := range lines {
		if !strings.Contains(line, ":") { //skip get post
			continue
		}
		index := strings.IndexByte(string(line), ':')
		key := line[:index]
		value := line[index+1:]
		//split := strings.Split(string(line), ":")   http:// ...  bug
		o.m[key] = strings.TrimSpace(string(value))
	}
	return true
}

func (o *object) String() string { //bug
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
	source, err := format.Source(buffer.Bytes())
	if !mylog.Error(err) {
		return ""
	}
	return string(source)
}

func (o *object) Map() map[string]string {
	return o.m
}

var Default = New()

func New() Interface {
	return &object{
		m: make(map[string]string),
	}
}
