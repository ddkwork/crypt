package des

import (
	"github.com/ddkwork/golibrary/mylog"
	"github.com/ddkwork/golibrary/stream"
)

func Encrypt[T stream.BinaryType](src, key T) (dst *stream.Stream) {
	s := stream.New(src)
	k := stream.New(key)
	if !s.CheckDesBlockSize() {
		return stream.New(mylog.Body())
	}
	if !k.CheckDesBlockSize() {
		return stream.New(mylog.Body())
	}
	subKeys := expand(k.Bytes())
	return stream.New(des_encrypt(s.Bytes(), subKeys))
}

func Decrypt[T stream.BinaryType](src, key T) (dst *stream.Stream) {
	s := stream.New(src)
	k := stream.New(key)
	if !s.CheckDesBlockSize() {
		return stream.New(mylog.Body())
	}
	if !k.CheckDesBlockSize() {
		return stream.New(mylog.Body())
	}
	subKeys := expand(k.Bytes())
	return stream.New(des_decrypt(s.Bytes(), subKeys))
}
