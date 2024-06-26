package unixTimestampConverter

import (
	_ "embed"
	"strconv"
	"time"

	"github.com/dop251/goja"

	"github.com/ddkwork/golibrary/mylog"
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
	mylog.Check2(runtime.RunString(jsBody))
	var fn func(string) string
	mylog.Check(runtime.ExportTo(runtime.Get("timestamp_to_date"), &fn))
	return fn(hexTimeStr)
}

func (o *object) FromBaseWith64Bit(hexTimeStr string, base int) string {
	integerTime := mylog.Check2(strconv.ParseInt(hexTimeStr, base, 64))
	integerTime /= 1000
	unixMicro := time.Unix(integerTime, 0)
	return unixMicro.Format(timeTemplate1)
}
func (o *object) FromUint32(hexTimeStr string) string  { return o.FromBaseWith64Bit(hexTimeStr, 16) }
func (o *object) FromInteger(hexTimeStr string) string { return o.FromBaseWith64Bit(hexTimeStr, 10) }

const timeTemplate1 = "2006-01-02 15:04:05"

func (o *object) UnixTimestamp() int64 { return time.Now().UnixNano() / 1e6 }

func New() Interface { return &object{} }
