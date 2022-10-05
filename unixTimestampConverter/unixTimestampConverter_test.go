package unixTimestampConverter

import (
	"github.com/ddkwork/golibrary/mylog"
	"github.com/dop251/goja"
	"testing"
)

func TestName(t *testing.T) {
	o := New()
	mylog.Hex("utc", o.UnixTimestamp())
	mylog.Info("utc", o.UnixTimestamp())
	println(o.FromInteger("1635091635282"))
	println(o.FromUint32("17CB31A4375"))
}

func TestJs(t *testing.T) {
	runtime := goja.New()
	_, err := runtime.RunString(jsBody)
	if err != nil {
		println(err.Error())
		return
	}
	var fn func(string) string
	err = runtime.ExportTo(runtime.Get("timestamp_to_date"), &fn)
	if err != nil {
		println(err.Error())
		return
	}
	s := fn("1634662111")
	println(s)
}
