package hash

import (
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/src/stream"
	"hash"
	"io"
)

func (o *object) setSum(hash hash.Hash) bool {
	_, err := io.WriteString(hash, o.src)
	if !mylog.Error(err) {
		return false
	}
	o.sum = stream.NewBytes(hash.Sum(nil)).HexString()
	return true
}
