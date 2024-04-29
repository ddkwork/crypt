package unixTimestampConverter

import (
	"testing"

	"github.com/dop251/goja"

	"github.com/ddkwork/golibrary/mylog"
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
	mylog.CheckFuncReturn(runtime.RunString(jsBody))
	var fn func(string) string
	if !mylog.Error(runtime.ExportTo(runtime.Get("timestamp_to_date"), &fn)) {
		return
	}
	s := fn("1634662111")
	println(s)
}
