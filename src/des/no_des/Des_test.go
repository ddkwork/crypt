package no_des

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDes(t *testing.T) {
	type IoStreamBuffer struct {
		Src []byte
		Key []byte
		Dst []byte
	}
	data := IoStreamBuffer{
		Src: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		Key: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		Dst: []byte{0xcd, 0x09, 0xbc, 0x48, 0x76, 0xac, 0x0f, 0x2b},
	}
	des := New()
	encode := des.Encode(data.Src, data.Key)
	assert.Equal(t, data.Dst, encode.Bytes())
	assert.Equal(t, "cd09bc4876ac0f2b", encode.HexString())

	decode := des.Decode(data.Dst, data.Key)
	assert.Equal(t, data.Src, decode.Bytes())
	assert.Equal(t, "1122334455667788", decode.HexString())
}
