package aes

import (
	"github.com/ddkwork/golibrary/safeType"
	"github.com/ddkwork/golibrary/stream"
)

func Encrypt[T safeType.BinaryType](src, key T) (dst *stream.Stream) {
	s := stream.New(src)
	k := stream.New(key) // todo  CheckAesBlockSize
	c := encrypt(s.Bytes(), k.Bytes())
	return stream.New(c[:])
}

func Decrypt[T safeType.BinaryType](src, key T) (dst *stream.Stream) {
	s := stream.New(src)
	k := stream.New(key)
	c := decrypt(s.Bytes(), k.Bytes())
	return stream.New(c[:])
}
