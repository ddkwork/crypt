package aes

import (
	"github.com/ddkwork/golibrary/stream"
)

func Encrypt[T stream.Type](src, key T) (dst *stream.Buffer) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key) // todo  CheckAesBlockSize
	c := encrypt(s.Bytes(), k.Bytes())
	return stream.NewBuffer(c[:])
}

func Decrypt[T stream.Type](src, key T) (dst *stream.Buffer) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	c := decrypt(s.Bytes(), k.Bytes())
	return stream.NewBuffer(c[:])
}
