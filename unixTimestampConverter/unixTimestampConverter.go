package unixTimestampConverter

import (
	_ "embed"
	"strconv"
	"time"

	"github.com/ddkwork/golibrary/mylog"
	"github.com/dop251/goja"
)

//go:embed time.js
var jsBody string

type (
	Interface interface {
		FromUint32(hexTimeStr string) string
		FromInteger(hexTimeStr string) string
		FromIntegerByJS(hexTimeStr string) string
		UnixTimestamp() int64
		// 使用time.ParseInLocation()而不是time.Parse()：
	}
	object struct{}
)

func (o *object) FromIntegerByJS(hexTimeStr string) string {
	runtime := goja.New()
	_, err := runtime.RunString(jsBody)
	if err != nil {
		return err.Error()
	}
	var fn func(string) string
	err = runtime.ExportTo(runtime.Get("timestamp_to_date"), &fn)
	if err != nil {
		return err.Error()
	}
	return fn(hexTimeStr)
}

func (o *object) FromBaseWith64Bit(hexTimeStr string, base int) string {
	integerTime, err := strconv.ParseInt(hexTimeStr, base, 64)
	if !mylog.Error(err) {
		return err.Error()
	}
	integerTime /= 1000
	unixMicro := time.Unix(integerTime, 0)
	return unixMicro.Format(timeTemplate1)
}
func (o *object) FromUint32(hexTimeStr string) string  { return o.FromBaseWith64Bit(hexTimeStr, 16) }
func (o *object) FromInteger(hexTimeStr string) string { return o.FromBaseWith64Bit(hexTimeStr, 10) }

const timeTemplate1 = "2006-01-02 15:04:05"

func (o *object) UnixTimestamp() int64 { return time.Now().UnixNano() / 1e6 }

var Default = New()

func New() Interface { return &object{} }
