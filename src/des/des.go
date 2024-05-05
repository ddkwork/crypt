package des

import (
	"github.com/ddkwork/golibrary/stream"
)

func Encrypt[T stream.Type](src, key T) (dst *stream.Buffer) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	s.CheckDesBlockSize()
	k.CheckDesBlockSize()
	subKeys := expand(k.Bytes())
	return stream.NewBuffer(des_encrypt(s.Bytes(), subKeys))
}

func Decrypt[T stream.Type](src, key T) (dst *stream.Buffer) {
	s := stream.NewBuffer(src)
	k := stream.NewBuffer(key)
	s.CheckDesBlockSize()
	k.CheckDesBlockSize()
	subKeys := expand(k.Bytes())
	return stream.NewBuffer(des_decrypt(s.Bytes(), subKeys))
}
