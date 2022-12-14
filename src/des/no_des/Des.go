package no_des

import (
	"crypto/des"
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/src/stream"
)

type (
	Interface interface {
		Encode(src, key any) *stream.Stream
		Decode(dst, key any) *stream.Stream
	}
	object struct{}
)

func New() Interface { return &object{} }
func (o *object) Encode(src, key any) *stream.Stream {
	s := stream.NewHexStringOrBytes(src)
	if !s.DesBlockSizeSizeCheck() {
		return s
	}
	k := stream.NewHexStringOrBytes(key)
	if !k.DesBlockSizeSizeCheck() {
		return k
	}
	block, err := des.NewCipher(k.Bytes())
	if !mylog.Error(err) {
		return nil
	}
	dst := make([]byte, des.BlockSize)
	block.Encrypt(dst, s.Bytes())
	return stream.NewBytes(dst)
}

func (o *object) Decode(dst, key any) *stream.Stream {
	d := stream.NewHexStringOrBytes(dst)
	if !d.DesBlockSizeSizeCheck() {
		return d
	}
	k := stream.NewHexStringOrBytes(key)
	if !k.DesBlockSizeSizeCheck() {
		return k
	}
	block, err := des.NewCipher(k.Bytes())
	if !mylog.Error(err) {
		return nil
	}
	src := make([]byte, des.BlockSize)
	block.Decrypt(src, d.Bytes())
	return stream.NewBytes(src)
}
