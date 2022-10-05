package hexStringDump

import (
    _ "embed"
    "github.com/stretchr/testify/assert"
    "testing"
)

//go:embed 1.bin
var src string

func TestName(t *testing.T) {
    h := New()
    assert.True(t, h.Convert(src))
    h.RemoveOffsetAndAscii()
    h.RemoveSpace()
}