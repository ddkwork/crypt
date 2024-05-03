package des

import (
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/safeType"
	"github.com/ddkwork/golibrary/stream"
)

func Encrypt[T safeType.BinaryType](src, key T) (dst *stream.Stream) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	if !s.CheckDesBlockSize() {
		return stream.NewBuffer(mylog.Body())
	}
	if !k.CheckDesBlockSize() {
		return stream.NewBuffer(mylog.Body())
	}
	subKeys := expand(k.Bytes())
	return stream.NewBuffer(des_encrypt(s.Bytes(), subKeys))
}

func Decrypt[T safeType.BinaryType](src, key T) (dst *stream.Stream) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	if !s.CheckDesBlockSize() {
		return stream.NewBuffer(mylog.Body())
	}
	if !k.CheckDesBlockSize() {
		return stream.NewBuffer(mylog.Body())
	}
	subKeys := expand(k.Bytes())
	return stream.NewBuffer(des_decrypt(s.Bytes(), subKeys))
}
