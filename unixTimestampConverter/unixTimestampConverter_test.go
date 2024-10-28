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
	mylog.Check2(runtime.RunString(jsBody))
	var fn func(string) string
	mylog.Check(runtime.ExportTo(runtime.Get("timestamp_to_date"), &fn))
	s := fn("1634662111")
	println(s)
}
