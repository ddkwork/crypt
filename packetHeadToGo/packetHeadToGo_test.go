package packetHeadToGo

import (
	_ "embed"
	"testing"

	"github.com/ddkwork/golibrary/assert"
	"github.com/ddkwork/golibrary/mylog"
)

//go:embed 1.bin
var src string

func TestName(t *testing.T) {
	p := New()
	assert.True(t, p.Convert(src))
	mylog.Json("", p.String())
}
