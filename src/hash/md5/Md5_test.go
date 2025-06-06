package md5

import (
	"testing"

	"github.com/ddkwork/golibrary/std/stream"

	"github.com/ddkwork/golibrary/std/assert"
)

func TestMD5(t *testing.T) {
	md5 := New()
	sum := md5.Sum("DiskGetor")
	assert.Equal(t, stream.HexString("3416eb58035074b9c53873316d364f2f"), sum.HexString())
	sum2 := md5.Sum2("DiskGetor")
	assert.Equal(t, stream.HexString("3416eb58035074b9c53873316d364f2f"), sum2.HexString())
}
